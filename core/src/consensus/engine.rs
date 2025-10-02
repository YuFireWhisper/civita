use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bincode::error::DecodeError;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::ResponseChannel,
    Multiaddr, PeerId,
};
use multihash_derive::MultihashDigest;
use rocksdb::{Options, DB};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    consensus::graph::{self, Graph, Proofs, RejectReason, Status},
    crypto::Multihash,
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        transport, Gossipsub, Transport,
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

    #[error("Atom is rejected, reason: {0:?}")]
    Rejected(RejectReason),

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
    #[error(transparent)]
    Gossipsub(#[from] gossipsub::Error),

    #[error(transparent)]
    Transport(#[from] transport::Error),

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

#[derive(serde::Serialize, serde::Deserialize)]
enum Request {
    Atoms(HashSet<Multihash>),
    Blocks(u32),
    InitialState(PeerId),
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Config", deserialize = "T: Config"))]
enum Response<T: Config> {
    Atoms(Vec<Atom<T>>),
    Blocks(Vec<Atom<T>>),
    InitialState(Box<(Atom<T>, Proofs<T>)>),
}

#[derive(Clone, Copy)]
pub enum NodeType {
    Archive,
    Regular(PeerId),
}

#[derive(Clone)]
pub struct BootstrapConfig {
    pub peers: Vec<(PeerId, Multiaddr)>,
    pub timeout: tokio::time::Duration,
    pub node_type: NodeType,
}

#[derive(Clone, Copy)]
pub struct EngineConfig {
    pub gossip_topic: u8,
    pub heartbeat_interval: Option<tokio::time::Duration>,
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
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,

    graph: Graph<T>,

    pending_atoms: HashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    atom_result_tx: Sender<Atom<T>>,

    gossip_topic: u8,
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
        transport: Arc<Transport>,
        dir: &str,
        bootstrap: Option<BootstrapConfig>,
        config: EngineConfig,
    ) -> Result<Handle<T>> {
        let gossipsub = transport.gossipsub();
        let req_resp = transport.request_response();
        let (atom_result_tx, atom_result_rx) = tokio::sync::mpsc::channel(100);
        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;

        let (graph, db, node_type) = if let Some(bootstrap_config) = bootstrap {
            if bootstrap_config.peers.is_empty() {
                return Err(Error::NoBootstrapPeers);
            }
            Self::bootstrap(&transport, dir, bootstrap_config).await?
        } else {
            let (mmr, proofs) = Self::create_genesis_mmr();
            let genesis = Self::create_genesis_atom(mmr.peak_hashes());

            let mut graph = Graph::new(genesis, None);
            graph.fill(proofs);

            let db = Self::open_db(dir)?;

            (graph, Some(db), NodeType::Archive)
        };

        let engine = Self {
            transport: transport.clone(),
            gossipsub,
            request_response: req_resp,
            gossip_topic: config.gossip_topic,
            graph,
            pending_atoms: HashMap::new(),
            atom_result_tx,
            heartbeat_interval: config.heartbeat_interval,
            db,
            node_type,
        };

        let (request_tx, request_rx) = tokio::sync::mpsc::channel(100);

        tokio::spawn(async move {
            engine.run(gossip_rx, atom_result_rx, request_rx).await;
        });

        Ok(Handle(request_tx))
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
        use crate::ty::atom::AtomBuilder;

        let genesis_hash = Multihash::default();
        AtomBuilder::new(
            genesis_hash,
            T::GENESIS_HEIGHT,
            T::GENESIS_VAF_DIFFICULTY,
            peaks,
        )
        .with_command(T::genesis_command())
        .with_random(0)
        .with_timestamp(0)
        .build_sync()
    }

    fn open_db(dir: &str) -> Result<DB> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        DB::open(&opts, dir).map_err(Error::from)
    }

    async fn bootstrap(
        transport: &Transport,
        dir: &str,
        bootstrap_config: BootstrapConfig,
    ) -> Result<(Graph<T>, Option<DB>, NodeType)> {
        let mut peers = HashSet::with_capacity(bootstrap_config.peers.len());

        for (peer, addr) in bootstrap_config.peers {
            transport.dial(peer, addr).await?;
            peers.insert(peer);
        }

        tokio::time::timeout(bootstrap_config.timeout, async {
            match bootstrap_config.node_type {
                NodeType::Archive => Self::bootstrap_archive(transport, dir, &peers)
                    .await
                    .map(|(g, d)| (g, Some(d), NodeType::Archive)),
                NodeType::Regular(peer_id) => Self::bootstrap_regular(transport, peer_id, &peers)
                    .await
                    .map(|g| (g, None, NodeType::Regular(peer_id))),
            }
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)
        .and_then(|res| res)
    }

    async fn bootstrap_archive(
        transport: &Transport,
        dir: &str,
        peers: &HashSet<PeerId>,
    ) -> Result<(Graph<T>, DB)> {
        use bincode::{
            config,
            serde::{decode_from_slice, encode_to_vec},
        };

        let (mmr, proofs) = Self::create_genesis_mmr();
        let genesis = Self::create_genesis_atom(mmr.peak_hashes());

        let mut graph = Graph::new(genesis, None);
        graph.fill(proofs);

        let db = Self::open_db(dir)?;
        let iter = db.iterator(rocksdb::IteratorMode::Start);

        let mut exp = T::GENESIS_HEIGHT;
        for item in iter {
            let (_, value) = item?;

            let atom: Atom<T> = decode_from_slice(&value, config::standard())
                .map_err(|e| Error::Storage(StorageError::Decode(e)))?
                .0;

            if atom.height != exp {
                return Err(Error::Storage(StorageError::InvalidAtomHeight(
                    exp,
                    atom.height,
                )));
            }

            let hash = atom.hash();
            let result = graph.upsert(atom);

            if !result.rejected.is_empty() {
                return Err(Error::Storage(StorageError::Rejected(
                    result.rejected.into_iter().next().unwrap().1,
                )));
            }

            if !result.missing.is_empty() {
                return Err(Error::Storage(StorageError::MissingDependencies));
            }

            if graph.finalized() != hash {
                return Err(Error::Storage(StorageError::NotFinalized));
            }

            exp += 1;
        }

        let req_resp = transport.request_response();
        let mut cur_height = graph.finalized_height();

        loop {
            let req = Request::Blocks(cur_height);
            let msg = encode_to_vec(&req, config::standard()).unwrap();

            for peer in peers {
                req_resp.send_request(*peer, msg.clone()).await;
            }

            let atoms = Self::recv_blocks_response(&req_resp).await;

            if atoms.is_empty() {
                break;
            }

            if atoms
                .into_iter()
                .any(|a| !graph.upsert(a).rejected.is_empty())
            {
                log::warn!("Received invalid atom during bootstrap");
                continue;
            }

            cur_height = graph.finalized_height();
        }

        Ok((graph, db))
    }

    async fn recv_blocks_response(req_resp: &RequestResponse) -> Vec<Atom<T>> {
        use bincode::{config, serde::decode_from_slice};

        while let Some(msg) = req_resp.recv().await {
            let Message::Response { response, .. } = msg else {
                log::warn!("Expected response message, got request");
                continue;
            };

            let Ok((resp, _)) = decode_from_slice::<Response<T>, _>(&response, config::standard())
            else {
                log::warn!("Failed to decode response");
                continue;
            };

            if let Response::Blocks(atoms) = resp {
                return atoms;
            } else {
                log::warn!("Unexpected response type");
            }
        }

        panic!("channel closed");
    }

    async fn bootstrap_regular(
        transport: &Transport,
        peer_id: PeerId,
        peers: &HashSet<PeerId>,
    ) -> Result<Graph<T>> {
        use bincode::{config, serde::encode_to_vec};

        let req_resp = transport.request_response();

        let req = Request::InitialState(peer_id);
        let msg = encode_to_vec(&req, config::standard()).unwrap();

        for peer in peers {
            req_resp.send_request(*peer, msg.clone()).await;
        }

        let (initial_atom, proofs) = Self::recv_initial_state_response(&req_resp).await;
        let mut graph = Graph::new(initial_atom, Some(peer_id));

        if !graph.fill(proofs) {
            return Err(Error::InvalidInitialState);
        }

        let mut current_height = graph.finalized_height();

        loop {
            let req = Request::Blocks(current_height);
            let msg = encode_to_vec(&req, config::standard()).unwrap();

            for peer in peers {
                req_resp.send_request(*peer, msg.clone()).await;
            }

            let atoms = Self::recv_blocks_response(&req_resp).await;

            if atoms.is_empty() {
                break;
            }

            if atoms
                .into_iter()
                .any(|a| !graph.upsert(a).rejected.is_empty())
            {
                log::warn!("Received invalid atom during bootstrap");
                continue;
            }

            current_height = graph.finalized_height();
        }

        Ok(graph)
    }

    async fn recv_initial_state_response(req_resp: &RequestResponse) -> (Atom<T>, Proofs<T>) {
        use bincode::{config, serde::decode_from_slice};

        while let Some(msg) = req_resp.recv().await {
            let Message::Response { response, .. } = msg else {
                log::warn!("Expected response message, got request");
                continue;
            };

            let Ok((resp, _)) = decode_from_slice::<Response<T>, _>(&response, config::standard())
            else {
                log::warn!("Failed to decode response");
                continue;
            };

            if let Response::InitialState(boxed) = resp {
                return *boxed;
            } else {
                log::warn!("Unexpected response type");
            }
        }

        panic!("channel closed");
    }

    async fn run(
        mut self,
        mut gossip_rx: Receiver<gossipsub::Message>,
        mut atom_result_rx: Receiver<Atom<T>>,
        mut request_rx: Receiver<EngineRequest<T>>,
    ) {
        let mut hb_interval = self.heartbeat_interval.map(tokio::time::interval);

        loop {
            let mut gossip_msg = None;
            let mut req_resp_msg = None;
            let mut atom_result = None;
            let mut engine_request = None;
            let mut hb_tick = false;

            tokio::select! {
                Some(msg) = gossip_rx.recv() => {
                    gossip_msg = Some(msg);
                }
                Some(msg) = self.request_response.recv() => {
                    req_resp_msg = Some(msg);
                }
                Some(atom) = atom_result_rx.recv() => {
                    atom_result = Some(atom);
                }
                Some(req) = request_rx.recv() => {
                    engine_request = Some(req);
                }
                _ = async {
                    if let Some(ref mut interval) = hb_interval {
                        interval.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    hb_tick = true;
                }
            }

            if let Some(msg) = gossip_msg {
                self.handle_gossip_message(msg).await;
            }

            if let Some(msg) = req_resp_msg {
                self.on_recv_request_response(msg).await;
            }

            if let Some(atom) = atom_result {
                if self.on_atom_ready(atom).await {
                    if let Some(interval) = hb_interval.as_mut() {
                        interval.reset();
                    }
                }
            }

            if let Some(req) = engine_request {
                if self.handle_engine_request(req).await {
                    break;
                }
            }

            if hb_tick {
                let handle = self.graph.create_atom(None);
                let tx = self.atom_result_tx.clone();
                tokio::spawn(async move {
                    let atom = handle.await.expect("Atom creation failed");
                    if let Err(e) = tx.send(atom).await {
                        log::error!("Failed to send atom result: {e}");
                    }
                });
            }
        }

        log::info!("Engine stopped");
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
                let peer_id = self.transport.local_peer_id();
                let tokens = self.graph.tokens(&peer_id).unwrap();
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
        let peer_id = self.transport.local_peer_id();
        let cmd = self.graph.create_command(
            &peer_id,
            code,
            on_chain_inputs,
            off_chain_inputs,
            outputs,
        )?;
        let handle = self.graph.create_atom(Some(cmd));

        let tx = self.atom_result_tx.clone();

        tokio::spawn(async move {
            let atom = handle.await.expect("Atom creation failed");
            if let Err(e) = tx.send(atom).await {
                log::error!("Failed to send atom result: {e}");
            }
        });

        Ok(())
    }

    async fn handle_gossip_message(&mut self, msg: gossipsub::Message) {
        let Ok((atom, _)) = bincode::serde::decode_from_slice::<Atom<T>, _>(
            msg.data.as_slice(),
            bincode::config::standard(),
        ) else {
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        };

        self.on_recv_atom(atom, Some(msg.id), msg.propagation_source)
            .await;
    }

    async fn on_recv_atom(&mut self, atom: Atom<T>, msg_id: Option<MessageId>, peer: PeerId) {
        let hash = atom.hash();

        for hash in atom.atoms.iter().chain(&[atom.hash(), atom.parent]) {
            self.pending_atoms
                .entry(*hash)
                .or_default()
                .push((msg_id.clone(), peer));
        }

        let result = self.graph.upsert(atom);

        if let Some(ref db) = self.db {
            for finalized_hash in &result.finalized {
                if let Some(atom) = self.graph.get(finalized_hash) {
                    let height_key = atom.height.to_be_bytes();
                    let atom_data =
                        bincode::serde::encode_to_vec(atom, bincode::config::standard()).unwrap();
                    if let Err(e) = db.put(height_key, atom_data) {
                        log::error!("Failed to store finalized atom: {e}");
                    }
                }
            }
        }

        if result.existing {
            log::info!("Atom {hash:?} is already existing");
            if let Some(infos) = self.pending_atoms.remove(&hash) {
                for (msg_id, peer) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                    self.gossipsub
                        .report_validation_result(&msg_id, &peer, MessageAcceptance::Accept)
                        .await;
                }
            }
            return;
        }

        for hash in result.accepted {
            log::info!("Atom {hash:?} accepted");

            if let Some(infos) = self.pending_atoms.remove(&hash) {
                for (msg_id, peer_id) in
                    infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p)))
                {
                    self.gossipsub
                        .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Accept)
                        .await;
                }
            }
        }

        for (hash, reason) in result.rejected {
            log::info!("Atom {hash:?} rejected: {reason:?}");

            if let Some(infos) = self.pending_atoms.remove(&hash) {
                for (msg_id, peer_id) in infos {
                    if let Some(msg_id) = msg_id {
                        self.gossipsub
                            .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Reject)
                            .await;
                    }
                    self.disconnect_peer(peer_id).await;
                }
            }
        }

        if !result.missing.is_empty() {
            let req = Request::Atoms(result.missing);
            let msg = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
            self.request_response.send_request(peer, msg).await;
        }
    }

    async fn disconnect_peer(&self, source: PeerId) {
        if let Err(e) = self.transport.disconnect(source).await {
            log::error!("Failed to disconnect peer: {e}");
        }
    }

    async fn on_recv_request_response(&mut self, msg: Message) {
        use bincode::{config, serde::decode_from_slice};

        match msg {
            Message::Request {
                peer,
                request,
                channel,
            } => {
                let Ok((req, _)) = decode_from_slice::<Request, _>(&request, config::standard())
                else {
                    log::warn!("Failed to decode request from {peer:?}");
                    return;
                };

                match req {
                    Request::Atoms(hashes) => {
                        self.handle_atom_request(hashes, channel).await;
                    }
                    Request::Blocks(height) => {
                        self.handle_blocks_request(height, channel).await;
                    }
                    Request::InitialState(peer_id) => {
                        self.handle_initial_state_request(peer_id, channel).await;
                    }
                }
            }
            Message::Response { peer, response } => {
                let Ok((resp, _)) =
                    decode_from_slice::<Response<T>, _>(&response, config::standard())
                else {
                    log::warn!("Failed to decode response from {peer:?}");
                    return;
                };

                if let Response::Atoms(atoms) = resp {
                    for atom in atoms {
                        self.on_recv_atom(atom, None, peer).await;
                    }
                } else {
                    log::warn!("Unexpected response type from {peer:?}");
                }
            }
        }
    }

    async fn handle_atom_request(
        &self,
        hashes: HashSet<Multihash>,
        channel: ResponseChannel<Vec<u8>>,
    ) {
        if hashes.is_empty() {
            return;
        }

        let atoms: Vec<Atom<T>> = hashes
            .iter()
            .filter_map(|h| self.graph.get(h).cloned())
            .collect();

        let response = Response::<T>::Atoms(atoms);
        let data = bincode::serde::encode_to_vec(&response, bincode::config::standard()).unwrap();

        if let Err(e) = self.request_response.send_response(channel, data).await {
            log::error!("Failed to send atom response: {e}");
        }
    }

    async fn handle_blocks_request(&self, height: u32, channel: ResponseChannel<Vec<u8>>) {
        use bincode::{config, serde::encode_to_vec};

        let finalized_height = self.graph.finalized_height();

        if height > finalized_height {
            let atoms = self.graph.current_atoms();
            let response = Response::<T>::Blocks(atoms);
            let data = encode_to_vec(&response, config::standard()).unwrap();

            if let Err(e) = self.request_response.send_response(channel, data).await {
                log::error!("Failed to send blocks response: {e}");
            }
            return;
        }

        let Some(ref db) = self.db else {
            let response = Response::<T>::Blocks(vec![]);
            let data = encode_to_vec(&response, config::standard()).unwrap();
            if let Err(e) = self.request_response.send_response(channel, data).await {
                log::error!("Failed to send blocks response: {e}");
            }
            return;
        };

        let mut atoms = Vec::new();
        let max_height = (height + T::MAX_BLOCKS_PER_SYNC).min(finalized_height);

        for h in height..=max_height {
            let key = h.to_be_bytes();
            if let Ok(Some(data)) = db.get(key) {
                let Ok((atom, _)) =
                    bincode::serde::decode_from_slice::<Atom<T>, _>(&data, config::standard())
                else {
                    continue;
                };
                atoms.push(atom);
            }
        }

        let response = Response::<T>::Blocks(atoms);
        let data = encode_to_vec(&response, config::standard()).unwrap();

        if let Err(e) = self.request_response.send_response(channel, data).await {
            log::error!("Failed to send blocks response: {e}");
        }
    }

    async fn handle_initial_state_request(
        &self,
        peer_id: PeerId,
        channel: ResponseChannel<Vec<u8>>,
    ) {
        use bincode::{config, serde::encode_to_vec};

        if !matches!(self.node_type, NodeType::Archive) {
            return;
        }

        let finalized_height = self.graph.finalized_height();
        let start_height = finalized_height.saturating_sub(T::MAINTENANCE_WINDOW);

        let Some(ref db) = self.db else {
            return;
        };

        let initial_atom = if let Ok(Some(data)) = db.get(start_height.to_be_bytes()) {
            let Ok((atom, _)) =
                bincode::serde::decode_from_slice::<Atom<T>, _>(&data, config::standard())
            else {
                return;
            };
            atom
        } else {
            return;
        };

        let proofs = self.graph.tokens_and_proof(&peer_id).unwrap_or_default();

        let response = Response::InitialState(Box::new((initial_atom, proofs)));
        let data = encode_to_vec(&response, config::standard()).unwrap();

        if let Err(e) = self.request_response.send_response(channel, data).await {
            log::error!("Failed to send initial state response: {e}");
        }
    }

    async fn on_atom_ready(&mut self, atom: Atom<T>) -> bool {
        use bincode::{config, serde::encode_to_vec};

        let vec = encode_to_vec(&atom, config::standard()).unwrap();

        let result = self.graph.upsert(atom);

        if let Some(ref db) = self.db {
            for finalized_hash in &result.finalized {
                if let Some(atom) = self.graph.get(finalized_hash) {
                    let key = atom.height.to_be_bytes();
                    let value = encode_to_vec(atom, bincode::config::standard()).unwrap();
                    if let Err(e) = db.put(key, value) {
                        log::error!("Failed to store finalized atom: {e}");
                    }
                }
            }
        }

        if result.existing {
            return false;
        }

        if !result.rejected.is_empty() {
            log::error!("Locally created atom was rejected: {:?}", result.rejected);
            return false;
        }

        if let Err(e) = self.gossipsub.publish(self.gossip_topic, vec).await {
            log::error!("Failed to publish atom: {e}");
            return false;
        }

        true
    }
}

impl From<rocksdb::Error> for Error {
    fn from(value: rocksdb::Error) -> Self {
        Error::Storage(StorageError::Rocksdb(value))
    }
}
