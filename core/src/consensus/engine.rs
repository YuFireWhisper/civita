use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use bincode::error::DecodeError;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::ResponseChannel,
    PeerId,
};
use multihash_derive::MultihashDigest;
use rocksdb::{Options, DB};
use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
    task::{JoinHandle, JoinSet},
};

use crate::{
    consensus::graph::{self, Graph, Proofs, Reason, Status},
    crypto::Multihash,
    network::{
        transport::{Message, Request, Response},
        Transport,
    },
    traits::Config,
    ty::{atom::Atom, token::Token},
    utils::mmr::Mmr,
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Rocksdb(#[from] rocksdb::Error),

    #[error("Invalid atom height, expected {0}, got {1}")]
    InvalidAtomHeight(u32, u32),

    #[error("Atom dismissed: {0:?}")]
    Dismissed(Reason),

    #[error("Atom is missing dependencies")]
    MissingDependencies,

    #[error("Failed to decode atom from storage: {0}")]
    Decode(#[from] DecodeError),

    #[error("Atom should be finalized")]
    NotFinalized,
}

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Bootstrap peers is empty")]
    NoBootstrapPeers,

    #[error("Bootstrap timeout")]
    BootstrapTimeout,

    #[error(transparent)]
    Graph(#[from] graph::Error),

    #[error("Invalid initial state")]
    InvalidInitialState,

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error("Engine has been stopped")]
    EngineStopped,
}

#[derive(Clone, Copy)]
pub enum NodeType {
    Archive,
    Regular,
}

#[derive(Clone)]
pub struct BootstrapConfig {
    pub peers: HashSet<PeerId>,
    pub timeout: tokio::time::Duration,
    pub node_type: NodeType,
}

enum EngineRequest<T: Config> {
    Propose {
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
        response: oneshot::Sender<Result<(), graph::Error>>,
    },
    Tokens(oneshot::Sender<HashMap<Multihash, Token<T>>>),
    Status(oneshot::Sender<Status>),
    Stop(oneshot::Sender<()>),
}

pub struct Handle<T: Config>(Sender<EngineRequest<T>>);
pub struct Engine<T: Config> {
    transport: Transport<T>,
    graph: Graph<T>,
    pending_atoms: HashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    task_set: JoinSet<Atom<T>>,
    heartbeat_interval: Option<tokio::time::Duration>,
    db: Option<DB>,
    node_type: NodeType,
}

impl<T: Config> Handle<T> {
    pub async fn propose(
        &self,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) -> JoinHandle<Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        let req = EngineRequest::Propose {
            code,
            on_chain_inputs,
            off_chain_inputs,
            outputs,
            response: tx,
        };
        self.0.send(req).await.expect("Engine stopped");
        tokio::spawn(async move { rx.await.expect("Engine stopped").map_err(|e| e.to_string()) })
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
        mut transport: Transport<T>,
        dir: &str,
        heartbeat_interval: Option<tokio::time::Duration>,
        bootstrap: Option<BootstrapConfig>,
    ) -> Result<Handle<T>> {
        let (graph, db, node_type) = if let Some(bootstrap_config) = bootstrap {
            if bootstrap_config.peers.is_empty() {
                return Err(Error::NoBootstrapPeers);
            }
            Self::bootstrap(&mut transport, dir, bootstrap_config).await?
        } else {
            let (mmr, proofs) = Self::create_genesis_mmr();
            let genesis = Self::create_genesis_atom(mmr.peak_hashes());

            let mut graph = Graph::new(genesis, None);
            graph.fill(proofs);

            let db = Self::open_db(dir)?;
            (graph, Some(db), NodeType::Archive)
        };

        let engine = Self {
            transport,
            graph,
            pending_atoms: HashMap::new(),
            task_set: JoinSet::new(),
            heartbeat_interval,
            db,
            node_type,
        };

        let (req_tx, req_rx) = mpsc::channel(1000);

        tokio::spawn(engine.run(req_rx));

        Ok(Handle(req_tx))
    }

    fn create_genesis_mmr() -> (Mmr, Proofs<T>) {
        use bincode::{config, serde::encode_into_std_write};

        let mut mmr = Mmr::default();

        let Some(cmd) = T::genesis_command() else {
            return (mmr, HashMap::new());
        };

        let mut tokens = HashMap::new();
        for (i, token) in cmd.outputs.into_iter().enumerate() {
            let mut buf = Vec::new();
            encode_into_std_write(Multihash::default(), &mut buf, config::standard()).unwrap();
            encode_into_std_write(i as u32, &mut buf, config::standard()).unwrap();
            let id = T::HASHER.digest(&buf);
            let idx = mmr.append(id);
            tokens.insert(id, (token, idx));
        }

        mmr.commit();

        let mut proofs = HashMap::new();
        for (id, (token, idx)) in tokens {
            let proof = mmr.prove(idx).expect("Proof should exist");
            proofs.insert(id, (token, proof));
        }

        (mmr, proofs)
    }

    fn create_genesis_atom(peaks: Vec<(u64, Multihash)>) -> Atom<T> {
        Atom::default()
            .with_parent(Multihash::default())
            .with_height(T::GENESIS_HEIGHT)
            .with_difficulty(T::GENESIS_VAF_DIFFICULTY)
            .with_peaks(peaks)
            .with_command(T::genesis_command())
    }

    fn open_db(dir: &str) -> Result<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        DB::open(&opts, dir).map_err(Error::from)
    }

    async fn bootstrap(
        transport: &mut Transport<T>,
        dir: &str,
        config: BootstrapConfig,
    ) -> Result<(Graph<T>, Option<DB>, NodeType)> {
        tokio::time::timeout(config.timeout, async {
            match config.node_type {
                NodeType::Archive => Self::bootstrap_archive(transport, dir, &config.peers)
                    .await
                    .map(|(g, d)| (g, Some(d), NodeType::Archive)),
                NodeType::Regular => Self::bootstrap_regular(transport, &config.peers)
                    .await
                    .map(|g| (g, None, NodeType::Regular)),
            }
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)
        .and_then(|res| res)
    }

    async fn bootstrap_archive(
        transport: &mut Transport<T>,
        dir: &str,
        peers: &HashSet<PeerId>,
    ) -> Result<(Graph<T>, DB)> {
        use bincode::{config, serde::decode_from_slice};

        let (mmr, proofs) = Self::create_genesis_mmr();
        let genesis = Self::create_genesis_atom(mmr.peak_hashes());

        let mut graph = Graph::new(genesis, None);
        graph.fill(proofs);

        let db = Self::open_db(dir)?;
        let mut height = 1u32;

        while let Some(value) = db.get(height.to_be_bytes())? {
            let block: Atom<T> = decode_from_slice(&value, config::standard())
                .map_err(|e| Error::Storage(StorageError::Decode(e)))?
                .0;

            if block.height != height {
                return Err(Error::Storage(StorageError::InvalidAtomHeight(
                    height,
                    block.height,
                )));
            }

            for hash in &block.atoms {
                let atoms = db
                    .get(hash.to_bytes())?
                    .ok_or(Error::Storage(StorageError::MissingDependencies))?;

                let atom: Atom<T> = decode_from_slice(&atoms, config::standard())
                    .map_err(|e| Error::Storage(StorageError::Decode(e)))?
                    .0;

                if atom.height != height {
                    return Err(Error::Storage(StorageError::InvalidAtomHeight(
                        height,
                        atom.height,
                    )));
                }

                let result = graph.upsert(atom);

                if !result.dismissed.is_empty() {
                    let reason = result.dismissed.into_iter().next().unwrap().1;
                    log::error!("Bootstrap dismissed: {reason:?}");
                    return Err(Error::Storage(StorageError::Dismissed(reason)));
                }

                if !result.missing.is_empty() {
                    return Err(Error::Storage(StorageError::MissingDependencies));
                }
            }

            let hash = block.hash();
            let result = graph.upsert(block);

            if !result.dismissed.is_empty() {
                let reason = result.dismissed.into_iter().next().unwrap().1;
                log::error!("Bootstrap dismissed: {reason:?}");
                return Err(Error::Storage(StorageError::Dismissed(reason)));
            }

            if !result.missing.is_empty() {
                return Err(Error::Storage(StorageError::MissingDependencies));
            }

            if graph.finalized() != hash {
                return Err(Error::Storage(StorageError::NotFinalized));
            }

            height += 1;
        }

        let mut cur_height = graph.finalized_height();

        loop {
            let req = Request::Blocks(cur_height);

            for peer in peers {
                transport.send_request(req.clone(), *peer).await;
            }

            let atoms = Self::recv_blocks_response(transport).await;

            if atoms.is_empty() {
                break;
            }

            if atoms
                .into_iter()
                .any(|a| !graph.upsert(a).dismissed.is_empty())
            {
                log::warn!("Received invalid atom during bootstrap");
                continue;
            }

            cur_height = graph.finalized_height();
        }

        Ok((graph, db))
    }

    async fn recv_blocks_response(transport: &mut Transport<T>) -> Vec<Atom<T>> {
        while let Some(msg) = transport.recv().await {
            let Message::Response { resp, .. } = msg else {
                log::warn!("Expected response message, got request");
                continue;
            };

            if let Response::AlreadyUpToDate = resp {
                return Vec::new();
            }

            if let Response::Blocks(atoms) = resp {
                return atoms;
            } else {
                log::warn!("Unexpected response type");
            }
        }

        panic!("channel closed");
    }

    async fn bootstrap_regular(
        transport: &mut Transport<T>,
        peers: &HashSet<PeerId>,
    ) -> Result<Graph<T>> {
        for peer in peers {
            log::info!("Sending state request to {}", peer);
            transport.send_request(Request::State, *peer).await;
        }

        let (initial_atom, proofs) = Self::recv_state_response(transport).await;
        let mut graph = Graph::new(initial_atom, Some(transport.peer_id));

        if !graph.fill(proofs) {
            return Err(Error::InvalidInitialState);
        }

        let mut current_height = graph.finalized_height();

        loop {
            let req = Request::Blocks(current_height);

            for peer in peers {
                transport.send_request(req.clone(), *peer).await;
            }

            let atoms = Self::recv_blocks_response(transport).await;

            if atoms.is_empty() {
                break;
            }

            if atoms
                .into_iter()
                .any(|a| !graph.upsert(a).dismissed.is_empty())
            {
                log::warn!("Received invalid atom during bootstrap");
                continue;
            }

            current_height = graph.finalized_height();
        }

        Ok(graph)
    }

    async fn recv_state_response(transport: &mut Transport<T>) -> (Atom<T>, Proofs<T>) {
        while let Some(msg) = transport.recv().await {
            let Message::Response { resp, .. } = msg else {
                continue;
            };

            if let Response::AlreadyUpToDate = resp {
                let (mmr, proofs) = Self::create_genesis_mmr();
                let atom = Self::create_genesis_atom(mmr.peak_hashes());
                return (atom, proofs);
            }

            if let Response::State(boxed) = resp {
                return *boxed;
            } else {
                log::warn!("Unexpected response type");
            }
        }

        panic!("channel closed");
    }

    async fn run(mut self, mut request_rx: Receiver<EngineRequest<T>>) {
        log::info!("Engine started");

        let mut hb_interval = self
            .heartbeat_interval
            .map(|d| tokio::time::interval(d))
            .unwrap_or(tokio::time::interval(tokio::time::Duration::MAX));

        loop {
            tokio::select! {
                Some(msg) = self.transport.recv() => {
                    match msg {
                        Message::Gossipsub { id, propagation_source, atom } => {
                            self.on_recv_atom(Some(id), propagation_source, *atom).await;
                        }
                        Message::Request { peer, req, channel } => {
                            self.on_recv_request(peer, req, channel).await;
                        }
                        Message::Response { peer, resp } => {
                            self.on_recv_response(peer, resp).await;
                        }
                    }
                }
                Some(req) = request_rx.recv() => {
                    if self.handle_engine_request(req).await {
                        break;
                    }
                }
                Some(Ok(atom)) = self.task_set.join_next() => {
                    if !self.on_atom_ready(atom).await {
                        let atom = self.graph.create_atom(None);
                        self.task_set.spawn_blocking(|| atom.solve());
                        hb_interval.reset();
                    }
                }
                _ = hb_interval.tick() => {
                    let atom = self.graph.create_atom(None);
                    self.task_set.spawn_blocking(|| atom.solve());
                }
            }

            tokio::task::yield_now().await;
        }

        log::info!("Engine stopped");
    }

    async fn on_recv_atom(&mut self, msg_id: Option<MessageId>, peer: PeerId, atom: Atom<T>) {
        for hash in atom.atoms.iter().chain(&[atom.hash(), atom.parent]) {
            self.pending_atoms
                .entry(*hash)
                .or_default()
                .push((msg_id.clone(), peer));
        }

        let result = self.graph.upsert(atom);

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

        if !result.missing.is_empty() {
            let req = Request::Atoms(result.missing);
            self.transport.send_request(req, peer).await;
        }

        self.on_finalized(&result.finalized);
    }

    fn on_finalized(&self, hashes: &[Multihash]) {
        use bincode::{config, serde::encode_to_vec};

        if hashes.is_empty() {
            return;
        }

        // let Some(ref db) = self.db else {
        //     return;
        // };

        for hash in hashes {
            let hex = hex::encode(hash.to_bytes());
            let atom = self.graph.get(hash).expect("Finalized atom should exist");

            log::info!("Atom finalized: {hex}, height {}", atom.height);

            let Some(ref db) = self.db else {
                continue;
            };

            let key = atom.height.to_be_bytes();
            let value = encode_to_vec(atom, config::standard()).unwrap();
            if let Err(e) = db.put(key, value) {
                log::error!("Failed to store finalized atom: {e}");
                return;
            }

            for hash in &atom.atoms {
                let atom = self.graph.get(hash).expect("Finalized atom should exist");
                let key = atom.hash().to_bytes();
                let value = encode_to_vec(atom, config::standard()).unwrap();
                if let Err(e) = db.put(key, value) {
                    log::error!("Failed to store finalized atom: {e}");
                    return;
                }
            }
        }
    }

    async fn on_recv_request(
        &mut self,
        peer: PeerId,
        request: Request,
        channel: ResponseChannel<Response<T>>,
    ) {
        match request {
            Request::Atoms(hashes) => {
                self.handle_atom_request(hashes, channel).await;
            }
            Request::Blocks(height) => {
                self.handle_blocks_request(height, channel).await;
            }
            Request::State => {
                self.handle_state_request(peer, channel).await;
            }
        }
    }

    async fn handle_atom_request(
        &self,
        hashes: HashSet<Multihash>,
        channel: ResponseChannel<Response<T>>,
    ) {
        if hashes.is_empty() {
            return;
        }

        let Some(atoms) = hashes.into_iter().try_fold(Vec::new(), |mut acc, hash| {
            self.graph.get(&hash).map(|atom| {
                acc.push(atom.clone());
                acc
            })
        }) else {
            return;
        };

        let resp = Response::<T>::Atoms(atoms);
        self.transport.send_response(resp, channel).await;
    }

    async fn handle_blocks_request(&self, height: u32, channel: ResponseChannel<Response<T>>) {
        use bincode::{config, serde::decode_from_slice};

        let Some(ref db) = self.db else {
            return;
        };

        let finalized_height = self.graph.finalized_height();

        if height >= finalized_height {
            let resp = Response::<T>::AlreadyUpToDate;
            self.transport.send_response(resp, channel).await;
            return;
        }

        let mut atoms = Vec::new();
        let max_height = (height + T::MAX_BLOCKS_PER_SYNC).min(finalized_height);

        for h in height..=max_height {
            let Ok(Some(data)) = db.get(h.to_be_bytes()) else {
                log::warn!("Missing block at height {h}");
                return;
            };

            let Ok((atom, _)) = decode_from_slice::<Atom<T>, _>(&data, config::standard()) else {
                return;
            };

            for hash in &atom.atoms {
                let bytes = hash.to_bytes();

                let Ok(Some(data)) = db.get(&bytes) else {
                    let hex = hex::encode(bytes);
                    log::warn!("Missing atom {hex} at height {h}");
                    return;
                };

                let Ok((atom, _)) = decode_from_slice::<Atom<T>, _>(&data, config::standard())
                else {
                    return;
                };

                atoms.push(atom);
            }

            atoms.push(atom);
        }

        let resp = Response::<T>::Blocks(atoms);
        self.transport.send_response(resp, channel).await;
    }

    async fn handle_state_request(&self, peer_id: PeerId, channel: ResponseChannel<Response<T>>) {
        use bincode::{config, serde::decode_from_slice};

        if !matches!(self.node_type, NodeType::Archive) {
            return;
        }

        let finalized_height = self.graph.finalized_height();
        let start_height = finalized_height.saturating_sub(T::MAINTENANCE_WINDOW);

        if start_height == 0 {
            let resp = Response::AlreadyUpToDate;
            self.transport.send_response(resp, channel).await;
            return;
        }

        let Some(ref db) = self.db else {
            return;
        };

        let Some(atom) = db
            .get(start_height.to_be_bytes())
            .ok()
            .flatten()
            .and_then(|res| {
                decode_from_slice::<Atom<T>, _>(&res, config::standard())
                    .map(|(atom, _)| atom)
                    .ok()
            })
        else {
            return;
        };

        let proofs = self.graph.tokens_and_proof(&peer_id).unwrap_or_default();
        let resp = Response::State(Box::new((atom, proofs)));
        self.transport.send_response(resp, channel).await;
    }

    async fn on_recv_response(&mut self, peer: PeerId, response: Response<T>) {
        let Response::Atoms(atoms) = response else {
            return;
        };

        for atom in atoms {
            self.on_recv_atom(None, peer, atom).await;
        }
    }

    async fn handle_engine_request(&mut self, request: EngineRequest<T>) -> bool {
        match request {
            EngineRequest::Propose {
                code,
                on_chain_inputs,
                off_chain_inputs,
                outputs,
                response,
            } => {
                let result = self
                    .propose(code, on_chain_inputs, off_chain_inputs, outputs)
                    .await;
                let _ = response.send(result);
                false
            }
            EngineRequest::Tokens(tx) => {
                let tokens = self.graph.tokens(&self.transport.peer_id).unwrap();
                let _ = tx.send(tokens);
                false
            }
            EngineRequest::Status(tx) => {
                let status = self.graph.status();
                let _ = tx.send(status);
                false
            }
            EngineRequest::Stop(tx) => {
                let _ = tx.send(());
                true
            }
        }
    }

    async fn propose(
        &mut self,
        code: u8,
        on_chain_inputs: Vec<(Multihash, T::ScriptSig)>,
        off_chain_inputs: Vec<T::OffChainInput>,
        outputs: Vec<Token<T>>,
    ) -> Result<(), graph::Error> {
        let cmd = self.graph.create_command(
            &self.transport.peer_id,
            code,
            on_chain_inputs,
            off_chain_inputs,
            outputs,
        )?;

        let atom = self.graph.create_atom(Some(cmd));
        self.task_set.spawn_blocking(|| atom.solve());

        Ok(())
    }

    async fn on_atom_ready(&mut self, atom: Atom<T>) -> bool {
        let hash = atom.hash();
        let result = self.graph.upsert(atom);

        if !result.dismissed.is_empty() || !result.missing.is_empty() {
            return false;
        }

        if !result.finalized.is_empty() {
            let hex = hex::encode(hash.to_bytes());
            let height = self.graph.get(&hash).unwrap().height;
            log::info!("Atom finalized: {hex}, height {height}");
        }

        let atom = self.graph.get(&hash).expect("Finalized atom should exist");
        self.transport.publish(atom.clone()).await;
        self.on_finalized(&result.finalized);

        true
    }
}

impl From<rocksdb::Error> for Error {
    fn from(value: rocksdb::Error) -> Self {
        Error::Storage(StorageError::Rocksdb(value))
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
