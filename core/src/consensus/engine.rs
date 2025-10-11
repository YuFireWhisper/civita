use std::{collections::HashMap, fmt};

use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::ResponseChannel,
    PeerId,
};
use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
    task::{JoinHandle, JoinSet},
};

use crate::{
    consensus::{
        engine::bootstraper::Bootstraper,
        tree::{Status, Tree},
    },
    crypto::Multihash,
    network::{
        transport::{Message, Request, Response},
        Transport,
    },
    traits::Config,
    ty::{atom::Atom, token::Token},
};

pub const MMR_DIR: &str = "mmr";
pub const OWNER_DIR: &str = "owner";
pub const ATOM_DIR: &str = "atom";

mod bootstraper;

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

enum EngineRequest<T: Config> {
    Propose(
        u8,
        Vec<(Multihash, T::ScriptSig)>,
        Vec<T::OffChainInput>,
        Vec<Token<T>>,
    ),
    Tokens(oneshot::Sender<HashMap<Multihash, Token<T>>>),
    Status(oneshot::Sender<Status>),
    Stop(oneshot::Sender<()>),
}

pub struct Handle<T: Config>(Sender<EngineRequest<T>>);
pub struct Engine<T: Config> {
    transport: Transport<T>,
    tree: Tree<T>,
    pending_atoms: HashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    task_set: JoinSet<Atom<T>>,
    heartbeat_interval: tokio::time::Interval,
    is_archive: bool,
}

impl<T: Config> Handle<T> {
    pub async fn propose(
        &self,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) {
        let req = EngineRequest::Propose(code, on_chain_inputs, off_chain_inputs, outputs);
        self.0.send(req).await.expect("Engine stopped");
    }

    pub async fn tokens(&self) -> JoinHandle<HashMap<Multihash, Token<T>>> {
        let (tx, rx) = oneshot::channel();
        let req = EngineRequest::Tokens(tx);
        self.0.send(req).await.expect("Engine stopped");
        tokio::spawn(async move { rx.await.expect("Engine stopped") })
    }

    pub async fn status(&self) -> JoinHandle<Status> {
        let (tx, rx) = oneshot::channel();
        let req = EngineRequest::Status(tx);
        self.0.send(req).await.expect("Engine stopped");
        tokio::spawn(async move { rx.await.expect("Engine stopped") })
    }

    pub async fn stop(self) {
        let (tx, rx) = oneshot::channel();
        let req = EngineRequest::Stop(tx);
        if self.0.send(req).await.is_ok() {
            let _ = rx.await;
        }
    }
}

impl<T: Config> Engine<T> {
    pub async fn spawn(
        transport: Transport<T>,
        dir: &str,
        heartbeat_interval: Option<tokio::time::Duration>,
        bootstrap: Option<BootstrapConfig>,
    ) -> Handle<T> {
        let heartbeat_interval = heartbeat_interval
            .map(|d| tokio::time::interval(d))
            .unwrap_or(tokio::time::interval(tokio::time::Duration::MAX));

        let engine = if let Some(config) = bootstrap {
            let is_archive = matches!(config.node_type, NodeType::Archive);
            let mut bootstraper = Bootstraper::new(transport, config.peer, dir, is_archive);
            bootstraper.bootstrap().await;
            let (transport, tree) = bootstraper.take();
            Self {
                transport,
                tree,
                pending_atoms: HashMap::new(),
                task_set: JoinSet::new(),
                heartbeat_interval,
                is_archive,
            }
        } else {
            Self {
                transport,
                tree: Tree::load_or_genesis(dir).expect("Failed to load or create genesis"),
                pending_atoms: HashMap::new(),
                task_set: JoinSet::new(),
                heartbeat_interval,
                is_archive: true,
            }
        };
        let (req_tx, req_rx) = mpsc::channel(100);
        tokio::spawn(engine.run(req_rx));
        Handle(req_tx)
    }

    async fn run(mut self, mut request_rx: Receiver<EngineRequest<T>>) {
        log::info!("Engine started");

        loop {
            tokio::select! {
                msg = self.transport.recv() => {
                    match msg {
                        Message::Gossipsub { id, propagation_source, atom } => {
                            self.on_recv_atom(Some(id), propagation_source, *atom).await;
                        }
                        Message::Request { peer, req, channel } => {
                            self.on_recv_request(peer, req, channel).await;
                        }
                        Message::Response { peer, resp } => {
                            if let Response::Atom(atom) = resp {
                                self.on_recv_atom(None, peer, *atom).await;
                            }
                        }
                    }
                }
                Some(req) = request_rx.recv() => {
                    match req {
                        EngineRequest::Propose(code, on_chain, off_chain, outputs) => {
                            self.propose(code, on_chain, off_chain, outputs).await;
                        }
                        EngineRequest::Tokens(tx) => {
                            let _ = tx.send(self.tree.tokens(&self.transport.peer_id));
                        }
                        EngineRequest::Status(tx) => {
                            let _ = tx.send(self.tree.status());
                        }
                        EngineRequest::Stop(tx) => {
                            let _ = tx.send(());
                            break;
                        }
                    }
                }
                Some(Ok(atom)) = self.task_set.join_next() => {
                    if !self.on_atom_ready(atom).await {
                        let atom = self.tree.create_atom(None);
                        self.task_set.spawn_blocking(|| atom.solve());
                        self.heartbeat_interval.reset();
                    }
                }
                _ = self.heartbeat_interval.tick() => {
                    let atom = self.tree.create_atom(None);
                    self.task_set.spawn_blocking(|| atom.solve());
                }
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

        let result = self.tree.upsert(atom);

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
            return;
        }

        match request {
            Request::AtomByHash(hash) => {
                if let Some(atom) = self.tree.get(&hash) {
                    let resp = Response::<T>::Atom(Box::new(atom.clone()));
                    self.transport.send_response(resp, channel).await;
                }
            }
            Request::AtomByHeight(height) => {
                if let Some(atom) = self.tree.get_by_height(height) {
                    let resp = Response::<T>::Atom(Box::new(atom));
                    self.transport.send_response(resp, channel).await;
                }
            }
            Request::CurrentHeight => {
                let resp = Response::<T>::CurrentHeight(self.tree.finalized_height());
                self.transport.send_response(resp, channel).await;
            }
            Request::Headers(start, end) => {
                if let Some(headers) = self.tree.headers(start, end) {
                    let resp = Response::<T>::Headers(headers);
                    self.transport.send_response(resp, channel).await;
                }
            }
            Request::Proofs => {
                let height = self.tree.finalized_height();
                let proofs = self.tree.proofs(&peer);
                let resp = Response::<T>::Proofs(height, proofs);
                self.transport.send_response(resp, channel).await;
            }
        }
    }

    async fn propose(
        &mut self,
        code: u8,
        on_chain: Vec<(Multihash, T::ScriptSig)>,
        off_chain: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) {
        let Some(cmd) =
            self.tree
                .create_command(&self.transport.peer_id, code, on_chain, off_chain, outputs)
        else {
            log::error!("Invalid command proposed");
            return;
        };
        let atom = self.tree.create_atom(Some(cmd));
        self.task_set.spawn_blocking(|| atom.solve());
    }

    async fn on_atom_ready(&mut self, atom: Atom<T>) -> bool {
        let result = self.tree.upsert(atom.clone());

        if !result.dismissed.is_empty() || result.missing.is_some() {
            return false;
        }

        self.transport.publish(atom).await;

        true
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::Archive => write!(f, "Archive"),
            NodeType::Regular => write!(f, "Regular"),
        }
    }
}

impl<T: Config> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Config> Drop for Handle<T> {
    fn drop(&mut self) {
        let _ = self
            .0
            .clone()
            .try_send(EngineRequest::Stop(oneshot::channel().0));
    }
}
