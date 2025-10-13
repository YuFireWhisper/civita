use std::{
    collections::{HashMap, VecDeque},
    fmt,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::ResponseChannel,
    PeerId,
};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

use crate::{
    consensus::tree::Tree,
    crypto::Multihash,
    event::{Event, Proposal},
    network::{
        transport::{Request, Response},
        Transport,
    },
    traits::Config,
    ty::atom::Atom,
};

const MAX_ATOMS_PER_REQUEST: u32 = 1000;

#[derive(Clone, Copy)]
pub enum NodeType {
    Archive,
    Regular,
}

#[derive(Clone)]
pub struct BootstrapConfig {
    pub peer: PeerId,
    pub timeout: tokio::time::Duration,
    pub node_type: NodeType,
}

pub struct Engine<T: Config> {
    transport: Transport<T>,
    tree: Tree<T>,
    pending_atoms: HashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    pending_tasks: VecDeque<Proposal<T>>,
    is_running_task: Arc<AtomicBool>,
    heartbeat_instant: tokio::time::Instant,
    heartbeat_duration: Duration,
    is_archive: bool,
}

impl<T: Config> Engine<T> {
    pub async fn spawn(
        mut transport: Transport<T>,
        dir: &str,
        heartbeat_duration: Option<tokio::time::Duration>,
        bootstrap: Option<BootstrapConfig>,
        tx: mpsc::Sender<Event<T>>,
        mut rx: mpsc::Receiver<Event<T>>,
    ) {
        let heartbeat_duration = heartbeat_duration.unwrap_or(Duration::MAX);
        let heartbeat_instant = Instant::now() + heartbeat_duration;

        let engine = if let Some(config) = bootstrap {
            let is_archive = matches!(config.node_type, NodeType::Archive);
            let tree = Self::bootstrap(&mut transport, &mut rx, config, dir).await;
            Self {
                transport,
                tree,
                pending_atoms: HashMap::new(),
                pending_tasks: VecDeque::new(),
                is_running_task: Arc::new(AtomicBool::new(false)),
                heartbeat_instant,
                heartbeat_duration,
                is_archive,
            }
        } else {
            Self {
                transport,
                tree: Tree::load_or_genesis(dir).expect("Failed to load or create genesis"),
                pending_atoms: HashMap::new(),
                pending_tasks: VecDeque::new(),
                is_running_task: Arc::new(AtomicBool::new(false)),
                heartbeat_instant,
                heartbeat_duration,
                is_archive: true,
            }
        };

        tokio::spawn(engine.run(tx, rx));
    }

    async fn bootstrap<P>(
        transport: &mut Transport<T>,
        rx: &mut Receiver<Event<T>>,
        config: BootstrapConfig,
        dir: P,
    ) -> Tree<T>
    where
        P: AsRef<Path>,
    {
        let mut tree_opt = match config.node_type {
            NodeType::Archive => {
                Some(Tree::load_or_genesis(&dir).expect("Failed to load or create genesis"))
            }
            NodeType::Regular => None,
        };

        loop {
            let req = Request::CurrentHeight;
            transport.send_request(req, config.peer).await;

            let local_height = tree_opt
                .as_ref()
                .map(|t| t.head_height())
                .unwrap_or_default();

            let remote_height = recv_response(rx, |resp| {
                if let Response::CurrentHeight(height) = resp {
                    Some(height)
                } else {
                    None
                }
            })
            .await;

            if remote_height < local_height {
                return tree_opt.expect("Tree should be initialized");
            }

            if remote_height == local_height {
                let tree =
                    tree_opt.get_or_insert_with(|| Tree::genesis(&dir, Some(transport.peer_id)));

                if !matches!(config.node_type, NodeType::Archive) {
                    let req = Request::Proofs;
                    transport.send_request(req, config.peer).await;

                    let (height, proofs) = recv_response(rx, |resp| {
                        if let Response::Proofs(height, proofs) = resp {
                            Some((height, proofs))
                        } else {
                            None
                        }
                    })
                    .await;

                    if height != local_height {
                        continue;
                    }

                    assert!(tree.fill(proofs));
                }

                return tree_opt.expect("Tree should be initialized");
            }

            let start = if matches!(config.node_type, NodeType::Archive) {
                local_height + 1
            } else {
                remote_height.saturating_sub(T::MAINTENANCE_WINDOW).max(1)
            };
            let end = remote_height.min(start + MAX_ATOMS_PER_REQUEST - 1);

            if start == 1 {
                tree_opt.get_or_insert_with(|| Tree::genesis(&dir, Some(transport.peer_id)));
            }

            for i in start..=end {
                let req = Request::AtomByHeight(i);
                transport.send_request(req, config.peer).await;
                let atom = recv_response(rx, |resp| {
                    if let Response::Atom(atom) = resp {
                        Some(*atom)
                    } else {
                        None
                    }
                })
                .await;

                match &mut tree_opt {
                    Some(tree) => {
                        let hash = atom.hash();
                        let _ = tree.upsert(atom, true);
                        assert_eq!(tree.head(), hash);
                    }
                    None => {
                        tree_opt = Some(Tree::with_atom(atom, &dir, transport.peer_id));
                    }
                }
            }
        }
    }

    async fn run(mut self, tx: Sender<Event<T>>, mut rx: Receiver<Event<T>>) {
        log::info!("Engine started");

        while let Some(event) = rx.recv().await {
            match event {
                Event::Gossipsub(id, propagation_source, atom) => {
                    self.on_recv_atom(Some(id), propagation_source, *atom).await;
                }
                Event::Request(req, peer, channel) => {
                    self.on_recv_request(peer, req, channel).await;
                }
                Event::Response(resp, peer) => {
                    if let Response::Atom(atom) = resp {
                        self.on_recv_atom(None, peer, *atom).await;
                    }
                }
                Event::Propose(proposal) => {
                    self.pending_tasks.push_back(proposal);
                    self.heartbeat_instant = Instant::now() + self.heartbeat_duration;

                    if self.is_running_task.load(Ordering::Relaxed) {
                        continue;
                    }

                    let proposal = self.pending_tasks.pop_front().unwrap();
                    let Some(cmd) = self.tree.create_command(proposal, &self.transport.peer_id)
                    else {
                        log::error!("Invalid command proposed");
                        continue;
                    };
                    let atom = self.tree.create_atom(Some(cmd));
                    let tx_clone = tx.clone();
                    let is_running_task = self.is_running_task.clone();
                    is_running_task.store(true, Ordering::Relaxed);

                    tokio::task::spawn_blocking(move || {
                        let atom = atom.solve();
                        let _ = tx_clone.blocking_send(Event::AtomReady(Box::new(atom)));
                        is_running_task.store(false, Ordering::Relaxed);
                    });
                }
                Event::Tokens(tx) => {
                    let _ = tx.send(self.tree.tokens(&self.transport.peer_id));
                }
                Event::Status(tx) => {
                    let _ = tx.send(self.tree.status());
                }
                Event::Stop(tx) => {
                    let _ = tx.send(());
                    break;
                }
                Event::AtomReady(atom) => {
                    if !self.on_atom_ready(*atom).await {
                        log::error!("Heartbeat atom rejected");
                    }
                }
            }

            if tokio::time::Instant::now() >= self.heartbeat_instant {
                self.heartbeat_instant = Instant::now() + self.heartbeat_duration;

                if self.is_running_task.load(Ordering::Relaxed) {
                    continue;
                }

                if let Some(proposal) = self.pending_tasks.pop_front() {
                    let Some(cmd) = self.tree.create_command(proposal, &self.transport.peer_id)
                    else {
                        log::error!("Invalid command proposed");
                        continue;
                    };

                    let atom = self.tree.create_atom(Some(cmd));
                    let tx_clone = tx.clone();
                    let is_running_task = self.is_running_task.clone();
                    is_running_task.store(true, Ordering::Relaxed);

                    tokio::task::spawn_blocking(move || {
                        let atom = atom.solve();
                        let _ = tx_clone.blocking_send(Event::AtomReady(Box::new(atom)));
                        is_running_task.store(false, Ordering::Relaxed);
                    });

                    continue;
                }

                let atom = self.tree.create_atom(None);
                let tx_clone = tx.clone();
                let is_running_task = self.is_running_task.clone();
                is_running_task.store(true, Ordering::Relaxed);

                tokio::task::spawn_blocking(move || {
                    let atom = atom.solve();
                    let _ = tx_clone.blocking_send(Event::AtomReady(Box::new(atom)));
                    is_running_task.store(false, Ordering::Relaxed);
                });
            }

            tokio::task::yield_now().await;
        }

        log::info!("Engine stopped");
    }

    async fn on_recv_atom(&mut self, msg_id: Option<MessageId>, peer: PeerId, atom: Atom<T>) {
        atom.atoms_hashes()
            .iter()
            .chain(&[atom.hash(), atom.parent])
            .for_each(|hash| {
                self.pending_atoms
                    .entry(*hash)
                    .or_default()
                    .push((msg_id.clone(), peer));
            });

        let result = self.tree.upsert(atom, false);

        for hash in result.accepted {
            let Some(infos) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                self.transport
                    .report(msg_id, peer, MessageAcceptance::Accept)
                    .await;
            }
        }

        for (hash, reason) in result.dismissed {
            let hex = hex::encode(hash.to_bytes());
            log::debug!("Atom dismissed: {hex}, reason: {reason:?}");

            let Some(infos) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer) in infos {
                if reason.is_ignore() {
                    if let Some(msg_id) = msg_id {
                        self.transport
                            .report(msg_id, peer, MessageAcceptance::Ignore)
                            .await;
                    }
                    continue;
                }

                if let Some(msg_id) = msg_id {
                    self.transport
                        .report(msg_id, peer, MessageAcceptance::Reject)
                        .await;
                }
            }
        }

        if let Some(missing) = result.missing {
            let req = Request::AtomByHash(missing);
            self.transport.send_request(req, peer).await;
        }
    }

    async fn on_recv_request(
        &mut self,
        peer: PeerId,
        request: Request,
        channel: ResponseChannel<Response<T>>,
    ) {
        if !self.is_archive {
            let resp = Response::NotFound;
            self.transport.send_response(resp, channel).await;
            return;
        }

        match request {
            Request::AtomByHash(hash) => {
                let resp = self
                    .tree
                    .get(&hash)
                    .map(|atom| Response::Atom(Box::new(atom.clone())))
                    .unwrap_or(Response::NotFound);
                self.transport.send_response(resp, channel).await;
            }
            Request::AtomByHeight(height) => {
                let resp = self
                    .tree
                    .get_by_height(height)
                    .map(|atom| Response::Atom(Box::new(atom)))
                    .unwrap_or(Response::NotFound);
                self.transport.send_response(resp, channel).await;
            }
            Request::CurrentHeight => {
                let resp = Response::<T>::CurrentHeight(self.tree.finalized_height());
                self.transport.send_response(resp, channel).await;
            }
            Request::Proofs => {
                let height = self.tree.finalized_height();
                let proofs = self.tree.proofs(&peer);
                let resp = Response::<T>::Proofs(height, proofs);
                self.transport.send_response(resp, channel).await;
            }
        }
    }

    async fn on_atom_ready(&mut self, atom: Atom<T>) -> bool {
        let result = self.tree.upsert(atom.clone(), false);

        if !result.dismissed.is_empty() || result.missing.is_some() {
            return false;
        }

        self.transport.publish(atom).await;

        true
    }
}

async fn recv_response<T: Config, F, U>(rx: &mut Receiver<Event<T>>, f: F) -> U
where
    F: Fn(Response<T>) -> Option<U>,
{
    while let Some(event) = rx.recv().await {
        if let Event::Response(resp, _) = event {
            if let Some(result) = f(resp) {
                return result;
            }
        }
    }
    panic!("Channel closed");
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::Archive => write!(f, "Archive"),
            NodeType::Regular => write!(f, "Regular"),
        }
    }
}
