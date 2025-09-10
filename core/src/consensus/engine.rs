use std::{collections::HashSet, future, sync::Arc};

use dashmap::DashMap;
use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    request_response::ResponseChannel,
    Multiaddr, PeerId,
};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    RwLock,
};

use crate::{
    consensus::{
        graph::{self, Graph, StorageMode},
        validator::Validator,
    },
    crypto::{hasher::Hasher, Multihash},
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        transport, Gossipsub, Transport,
    },
    ty::{atom::Atom, token::Token},
    utils::mmr::Mmr,
};

type Result<T, E = Error> = std::result::Result<T, E>;

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
}

#[derive(serde::Serialize, serde::Deserialize)]
enum Request {
    Atoms(HashSet<Multihash>),
    Sync(Option<PeerId>),
}

pub struct Config {
    pub gossip_topic: u8,
    pub heartbeat_interval: Option<tokio::time::Duration>,
}

pub struct Engine<V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,

    gossip_topic: u8,

    graph: RwLock<Graph<V>>,

    pending_atoms: DashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    atom_result_tx: Sender<Atom>,

    heartbeat_interval: Option<tokio::time::Duration>,
}

impl<V: Validator> Engine<V> {
    pub async fn new(
        transport: Arc<Transport>,
        peers: Vec<(PeerId, Multiaddr)>,
        timeout: tokio::time::Duration,
        graph_config: graph::Config,
        config: Config,
    ) -> Result<Arc<Self>> {
        let gossipsub = transport.gossipsub();
        let req_resp = transport.request_response();
        let (atom_result_tx, atom_result_rx) = tokio::sync::mpsc::channel(100);
        let mut req_resp_rx = req_resp.take_receiver().await.unwrap();
        let graph =
            Self::bootstrap(&transport, &mut req_resp_rx, peers, timeout, graph_config).await?;
        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;

        let engine = Arc::new(Self {
            transport,
            gossipsub,
            request_response: req_resp,
            gossip_topic: config.gossip_topic,
            graph: RwLock::new(graph),
            pending_atoms: DashMap::new(),
            atom_result_tx,
            heartbeat_interval: config.heartbeat_interval,
        });

        let engine_clone = engine.clone();
        tokio::spawn(async move {
            engine_clone
                .run(gossip_rx, req_resp_rx, atom_result_rx)
                .await;
        });

        Ok(engine)
    }

    async fn bootstrap(
        transport: &Transport,
        rx: &mut Receiver<Message>,
        peers: Vec<(PeerId, Multiaddr)>,
        timeout: tokio::time::Duration,
        graph_config: graph::Config,
    ) -> Result<Graph<V>> {
        use bincode::{config, serde::encode_to_vec};

        debug_assert!(!peers.is_empty());

        let msg = {
            let target = match graph_config.storage_mode {
                StorageMode::General(peer_id) => Some(peer_id),
                _ => None,
            };
            encode_to_vec(Request::Sync(target), config::standard()).unwrap()
        };

        let req_resp = transport.request_response();
        let mut peers_set = HashSet::new();

        for (peer, addr) in &peers {
            transport.dial(*peer, addr.clone()).await?;
            req_resp.send_request(*peer, msg.clone()).await;
            peers_set.insert(*peer);
        }

        let graph = tokio::time::timeout(timeout, async {
            while let Some(msg) = rx.recv().await {
                let Message::Response { response, peer } = &msg else {
                    continue;
                };

                if !peers_set.contains(peer) {
                    continue;
                }

                if let Ok(graph) = Graph::import(response, graph_config.clone()) {
                    return Ok(graph);
                }
            }
            panic!("Channel closed before receiving response");
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)?;

        graph
    }

    pub async fn with_genesis(
        transport: Arc<Transport>,
        atom: Atom,
        mmr: Mmr<Token>,
        graph_config: graph::Config,
        config: Config,
    ) -> Result<Arc<Self>> {
        let gossipsub = transport.gossipsub();
        let request_response = transport.request_response();
        let (atom_result_tx, atom_result_rx) = tokio::sync::mpsc::channel(100);
        let graph = Graph::with_genesis(atom, mmr, graph_config);
        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;
        let req_resp_rx = request_response.take_receiver().await.unwrap();

        let engine = Arc::new(Self {
            transport,
            gossipsub,
            request_response,
            gossip_topic: config.gossip_topic,
            graph: RwLock::new(graph),
            pending_atoms: DashMap::new(),
            atom_result_tx,
            heartbeat_interval: config.heartbeat_interval,
        });

        let engine_clone = engine.clone();
        tokio::spawn(async move {
            engine_clone
                .run(gossip_rx, req_resp_rx, atom_result_rx)
                .await;
        });

        Ok(engine)
    }

    pub async fn propose(
        &self,
        code: u8,
        inputs: impl IntoIterator<Item = (Multihash, impl Into<Vec<u8>>)>,
        created: impl IntoIterator<Item = (impl Into<Vec<u8>>, impl Into<Vec<u8>>)>,
    ) -> Result<(), graph::Error> {
        let graph = self.graph.read().await;
        let cmd = graph.create_command(code, inputs, created)?;
        let handle = graph.create_atom(Some(cmd))?;
        drop(graph);

        let tx = self.atom_result_tx.clone();

        tokio::spawn(async move {
            let atom = handle.await.expect("Atom creation failed");
            if let Err(e) = tx.send(atom).await {
                log::error!("Failed to send VDF result: {e}");
            }
        });

        Ok(())
    }

    async fn run(
        &self,
        mut gossip_rx: Receiver<gossipsub::Message>,
        mut req_resp_rx: Receiver<Message>,
        mut atom_result_rx: Receiver<Atom>,
    ) {
        let mut hb_interval = self.heartbeat_interval.map(tokio::time::interval);

        loop {
            let mut gossip_msg = None;
            let mut req_resp_msg = None;
            let mut atom_result = None;
            let mut hb_tick = false;

            tokio::select! {
                Some(msg) = gossip_rx.recv() => {
                    gossip_msg = Some(msg);
                }
                Some(msg) = req_resp_rx.recv() => {
                    req_resp_msg = Some(msg);
                }
                Some(atom) = atom_result_rx.recv() => {
                    atom_result = Some(atom);
                }
                _ = async {
                    match hb_interval.as_mut() {
                        Some(interval) => interval.tick().await,
                        None => future::pending().await,
                    }
                } => {
                    hb_tick = true;
                }
            }

            if let Some(msg) = gossip_msg {
                self.handle_gossip_message(msg).await;
            }

            if let Some(msg) = req_resp_msg {
                self.on_recv_reqeust_response(msg).await;
            }

            if let Some(atom) = atom_result {
                if self.on_atom_ready(atom).await {
                    if let Some(i) = hb_interval.as_mut() {
                        i.reset()
                    }
                }
            }

            if hb_tick {
                let Ok(handle) = self.graph.read().await.create_atom(None) else {
                    log::error!("Failed to create heartbeat atom");
                    continue;
                };

                let tx = self.atom_result_tx.clone();

                tokio::spawn(async move {
                    let atom = handle.await.expect("Atom creation failed");
                    if let Err(e) = tx.send(atom).await {
                        log::error!("Failed to send VDF result: {e}");
                    }
                });
            }
        }
    }

    async fn handle_gossip_message(&self, msg: gossipsub::Message) {
        let Ok((atom, _)) = bincode::serde::decode_from_slice::<Atom, _>(
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

        if !Hasher::validate(&atom.hash, &atom.hash_input()) {
            log::warn!("Invalid atom hash from peer {}", msg.propagation_source);
            self.gossipsub
                .report_validation_result(
                    &msg.id,
                    &msg.propagation_source,
                    MessageAcceptance::Reject,
                )
                .await;
            return;
        }

        self.on_recv_atom(atom, Some(msg.id), msg.propagation_source)
            .await;
    }

    async fn on_recv_atom(&self, atom: Atom, msg_id: Option<MessageId>, peer: PeerId) {
        let hash = atom.hash;

        for hash in atom.atoms.iter().chain(&[atom.hash, atom.parent]) {
            self.pending_atoms
                .entry(*hash)
                .or_default()
                .push((msg_id.clone(), peer));
        }

        let Some(result) = self.graph.write().await.upsert(atom) else {
            log::info!("Atom {hash:?} is already existing");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                return;
            };

            for (msg_id, peer) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                self.gossipsub
                    .report_validation_result(&msg_id, &peer, MessageAcceptance::Ignore)
                    .await;
            }

            return;
        };

        for hash in result.accepted {
            log::info!("Atom {hash:?} accepted");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer_id) in infos.into_iter().filter_map(|(id, p)| id.map(|id| (id, p))) {
                self.gossipsub
                    .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Ignore)
                    .await;
            }
        }

        for (hash, reason) in result.rejected {
            log::info!("Atom {hash:?} rejected: {reason:?}");

            let Some((_, infos)) = self.pending_atoms.remove(&hash) else {
                continue;
            };

            for (msg_id, peer_id) in infos {
                if let Some(msg_id) = msg_id {
                    self.gossipsub
                        .report_validation_result(&msg_id, &peer_id, MessageAcceptance::Reject)
                        .await;
                } else {
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

    async fn on_recv_reqeust_response(&self, msg: Message) {
        match msg {
            Message::Request {
                peer,
                request,
                channel,
            } => {
                let Ok((req, _)) = bincode::serde::decode_from_slice::<Request, _>(
                    request.as_slice(),
                    bincode::config::standard(),
                ) else {
                    self.disconnect_peer(peer).await;
                    return;
                };

                match req {
                    Request::Atoms(hashes) => self.handle_atom_request(peer, hashes, channel).await,
                    Request::Sync(target) => self.handle_sync_request(peer, target, channel).await,
                }
            }
            Message::Response { peer, response } => {
                let (atoms, _) = bincode::serde::decode_from_slice::<Vec<Atom>, _>(
                    response.as_slice(),
                    bincode::config::standard(),
                )
                .unwrap_or_default();

                if atoms.is_empty() {
                    self.disconnect_peer(peer).await;
                    return;
                }

                for atom in atoms {
                    if !Hasher::validate(&atom.hash, &atom.hash_input()) {
                        log::warn!("Invalid atom hash from peer {peer}");
                        self.disconnect_peer(peer).await;
                        return;
                    }

                    self.on_recv_atom(atom, None, peer).await;
                }
            }
        }
    }

    async fn handle_atom_request(
        &self,
        peer: PeerId,
        hashes: HashSet<Multihash>,
        channel: ResponseChannel<Vec<u8>>,
    ) {
        if hashes.is_empty() {
            self.disconnect_peer(peer).await;
            return;
        }

        let vec = {
            let graph = self.graph.read().await;
            let Some(atoms) = hashes.iter().try_fold(Vec::new(), |mut acc, h| {
                acc.push(graph.get(h)?);
                Some(acc)
            }) else {
                self.disconnect_peer(peer).await;
                return;
            };
            bincode::serde::encode_to_vec(&atoms, bincode::config::standard()).unwrap()
        };

        if let Err(e) = self.request_response.send_response(channel, vec).await {
            log::error!("Failed to send response: {e}");
        }
    }

    async fn handle_sync_request(
        &self,
        peer: PeerId,
        target: Option<PeerId>,
        channel: ResponseChannel<Vec<u8>>,
    ) {
        let Some(data) = self.graph.read().await.export(target) else {
            self.disconnect_peer(peer).await;
            return;
        };

        if let Err(e) = self
            .request_response
            .send_response(channel, data.to_vec())
            .await
        {
            log::error!("Failed to send response: {e}");
        }
    }

    async fn on_atom_ready(&self, atom: Atom) -> bool {
        let hash = atom.hash;
        let vec = bincode::serde::encode_to_vec(&atom, bincode::config::standard()).unwrap();
        let Some(result) = self.graph.write().await.upsert(atom) else {
            return false;
        };

        if !result.rejected.is_empty() {
            debug_assert!(result.rejected.len() == 1);
            log::error!("Created atom was rejected: {:?}", result.rejected[&hash]);
            return false;
        }

        debug_assert!(result.accepted.contains(&hash));

        if let Err(e) = self.gossipsub.publish(self.gossip_topic, vec).await {
            log::error!("Failed to publish created atom: {e}");
        }

        true
    }

    pub async fn tokens(&self) -> Vec<Token> {
        self.graph
            .read()
            .await
            .tokens_for(&self.transport.local_peer_id())
    }
}
