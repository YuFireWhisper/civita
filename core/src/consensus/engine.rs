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
    ty::atom::Atom,
    validator::ValidatorEngine,
};

const MAX_ATOMS_PER_REQUEST: u32 = 1000;

#[derive(Clone, Copy)]
#[derive(PartialEq, Eq)]
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

pub struct Engine<V: ValidatorEngine> {
    transport: Transport,
    tree: Tree<V>,
    pending_atoms: HashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    pending_tasks: VecDeque<Proposal>,
    is_running_task: Arc<AtomicBool>,
    heartbeat_instant: tokio::time::Instant,
    heartbeat_duration: Duration,
    is_archive: bool,
}

impl<V: ValidatorEngine> Engine<V> {
    pub async fn spawn_genesis(
        transport: Transport,
        dir: &str,
        heartbeat_duration: Option<Duration>,
        tx: mpsc::Sender<Event>,
        rx: mpsc::Receiver<Event>,
        atom: Atom,
    ) {
        let engine = Self {
            transport,
            tree: Tree::new(atom, dir, None),
            pending_atoms: HashMap::new(),
            pending_tasks: VecDeque::new(),
            is_running_task: Arc::new(AtomicBool::new(false)),
            heartbeat_instant: Instant::now() + heartbeat_duration.unwrap_or(Duration::MAX),
            heartbeat_duration: heartbeat_duration.unwrap_or(Duration::MAX),
            is_archive: true,
        };

        tokio::spawn(engine.run(tx, rx));
    }

    pub async fn spawn(
        mut transport: Transport,
        dir: &str,
        heartbeat_duration: Option<Duration>,
        config: BootstrapConfig,
        tx: mpsc::Sender<Event>,
        mut rx: mpsc::Receiver<Event>,
    ) {
        let is_archive = matches!(config.node_type, NodeType::Archive);
        let tree = Self::bootstrap(&mut transport, &mut rx, config, dir).await;
        let engine = Self {
            transport,
            tree,
            pending_atoms: HashMap::new(),
            pending_tasks: VecDeque::new(),
            is_running_task: Arc::new(AtomicBool::new(false)),
            heartbeat_instant: Instant::now() + heartbeat_duration.unwrap_or(Duration::MAX),
            heartbeat_duration: heartbeat_duration.unwrap_or(Duration::MAX),
            is_archive,
        };

        tokio::spawn(engine.run(tx, rx));
    }

    async fn bootstrap<P>(
        transport: &mut Transport,
        rx: &mut Receiver<Event>,
        config: BootstrapConfig,
        dir: P,
    ) -> Tree<V>
    where
        P: AsRef<Path>,
    {
        let mut tree_opt: Option<Tree<V>> = None;

        loop {
            let req = Request::CurrentHeight;
            transport.send_request(req, config.peer).await;

            let remote_height = recv_response(rx, |resp| {
                if let Response::CurrentHeight(height) = resp {
                    Some(height)
                } else {
                    None
                }
            })
            .await;

            if let Some(tree) = &mut tree_opt {
                let local_height = tree.head_height();

                if local_height > remote_height {
                    return tree_opt.unwrap();
                }

                if local_height == remote_height && config.node_type != NodeType::Archive {
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

                return tree_opt.unwrap();
            }

            let start = tree_opt.as_ref().map(|t| t.head_height() + 1).unwrap_or(0);
            let end = remote_height.min(start + MAX_ATOMS_PER_REQUEST - 1);

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
                        let id = atom.id(tree.hasher());
                        let _ = tree.upsert(atom, true);
                        assert_eq!(tree.head(), id);
                    }
                    None => {
                        let peer =
                            (config.node_type != NodeType::Archive).then_some(transport.peer_id);
                        tree_opt = Some(Tree::new(atom, &dir, peer));
                    }
                }
            }
        }
    }

    async fn run(mut self, tx: Sender<Event>, mut rx: Receiver<Event>) {
        log::info!("Engine started");

        while let Some(event) = rx.recv().await {
            match event {
                Event::Gossipsub(id, propagation_source, atom) => {
                    self.on_recv_atom(Some(id), propagation_source, *atom).await;
                }
                Event::Response(Response::Atom(atom), peer) => {
                    self.on_recv_atom(None, peer, *atom).await;
                }
                Event::Request(req, peer, channel) => {
                    self.on_recv_request(peer, req, channel).await;
                }
                Event::Propose(proposal) => {
                    self.add_task(Some(proposal), false, &tx).await;
                }
                Event::Tokens(tx) => {
                    let _ = tx.send(self.tree.tokens(&self.transport.peer_id));
                }
                Event::Status(tx) => {
                    let _ = tx.send(self.tree.status());
                }
                Event::SetNextChainConfig(height, config) => {
                    self.tree.set_next_chain_config(height, config);
                }
                Event::Stop(tx) => {
                    let _ = tx.send(());
                    break;
                }
                Event::AtomReady(atom) => {
                    if !self.on_atom_ready(*atom).await {
                        log::error!("Heartbeat atom rejected");
                    }
                    self.add_task(None, false, &tx).await;
                }
                _ => {}
            }

            if tokio::time::Instant::now() >= self.heartbeat_instant {
                self.add_task(None, true, &tx).await;
            }

            tokio::task::yield_now().await;
        }

        log::info!("Engine stopped");
    }

    async fn add_task(&mut self, proposal: Option<Proposal>, or_empty: bool, tx: &Sender<Event>) {
        if let Some(proposal) = proposal {
            self.pending_tasks.push_back(proposal);
        }

        if self.is_running_task.load(Ordering::Relaxed) {
            return;
        }

        let cmd = std::iter::from_fn(|| self.pending_tasks.pop_front()).find_map(|proposal| {
            self.tree
                .create_command(proposal, &self.transport.peer_id)
                .or_else(|| {
                    log::error!("Invalid command proposed");
                    None
                })
        });

        if cmd.is_none() && !or_empty {
            return;
        }

        let tx_clone = tx.clone();
        let is_running_task = self.is_running_task.clone();
        is_running_task.store(true, Ordering::Relaxed);

        let handle = self.tree.create_atom(cmd);
        tokio::spawn(async move {
            let atom = handle.await.unwrap();
            let _ = tx_clone.send(Event::AtomReady(Box::new(atom))).await;
            is_running_task.store(false, Ordering::Relaxed);
        });

        self.heartbeat_instant = Instant::now() + self.heartbeat_duration;
    }

    async fn on_recv_atom(&mut self, msg_id: Option<MessageId>, peer: PeerId, atom: Atom) {
        atom.atoms_ids(self.tree.hasher())
            .iter()
            .chain(Some(&atom.id(self.tree.hasher())))
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
        channel: ResponseChannel<Response>,
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
                let resp = Response::CurrentHeight(self.tree.finalized_height());
                self.transport.send_response(resp, channel).await;
            }
            Request::Proofs => {
                let height = self.tree.finalized_height();
                let proofs = self.tree.proofs(&peer);
                let resp = Response::Proofs(height, proofs);
                self.transport.send_response(resp, channel).await;
            }
        }
    }

    async fn on_atom_ready(&mut self, atom: Atom) -> bool {
        let result = self.tree.upsert(atom.clone(), false);

        if !result.dismissed.is_empty() || result.missing.is_some() {
            return false;
        }

        self.transport.publish(atom).await;

        true
    }
}

async fn recv_response<F, U>(rx: &mut Receiver<Event>, f: F) -> U
where
    F: Fn(Response) -> Option<U>,
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
