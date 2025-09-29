use std::{
    collections::HashSet,
    fs::{self, File},
    future,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

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
        graph::{self, Graph, Status, HISTORY},
        validator::Validator,
    },
    crypto::Multihash,
    network::{
        gossipsub,
        request_response::{Message, RequestResponse},
        transport, Gossipsub, Transport,
    },
    ty::{atom::Atom, token::Token},
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

    #[error(transparent)]
    Graph(#[from] graph::Error),
}

#[derive(serde::Serialize, serde::Deserialize)]
enum Request {
    Atoms(HashSet<Multihash>),
    Sync(u32),
}

#[derive(Clone, Copy)]
pub struct Config {
    pub block_threshold: u32,
    pub checkpoint_distance: u32,
    pub target_block_time: u64,
    pub init_vdf_difficulty: u64,
    pub max_difficulty_adjustment: f32,
    pub vdf_params: u16,
    pub gossip_topic: u8,
    pub heartbeat_interval: Option<tokio::time::Duration>,
}

#[derive(Clone)]
pub struct BootstrapConfig {
    pub peers: Vec<(PeerId, Multiaddr)>,
    pub timeout: tokio::time::Duration,
}

pub struct Engine<V> {
    transport: Arc<Transport>,
    gossipsub: Arc<Gossipsub>,
    request_response: Arc<RequestResponse>,

    graph: RwLock<Graph<V>>,

    pending_atoms: DashMap<Multihash, Vec<(Option<MessageId>, PeerId)>>,
    atom_result_tx: Sender<Atom>,

    gossip_topic: u8,
    heartbeat_interval: Option<tokio::time::Duration>,
    path: PathBuf,
}

impl<V: Validator> Engine<V> {
    pub async fn new(
        transport: Arc<Transport>,
        dir: &str,
        bootstrap: Option<BootstrapConfig>,
        config: Config,
    ) -> Result<Arc<Self>> {
        let gossipsub = transport.gossipsub();
        let req_resp = transport.request_response();
        let (atom_result_tx, atom_result_rx) = tokio::sync::mpsc::channel(100);
        let gossip_rx = gossipsub.subscribe(config.gossip_topic).await?;
        let path = Path::new(dir).join(HISTORY);
        fs::create_dir_all(&path).expect("Failed to create storage dir");

        let graph = if let Some(bootstrap) = bootstrap {
            if bootstrap.peers.is_empty() {
                return Err(Error::NoBootstrapPeers);
            }
            Self::bootstrap(&transport, bootstrap.peers, bootstrap.timeout, dir, config).await?
        } else {
            let graph_config = graph::Config {
                block_threshold: config.block_threshold,
                checkpoint_distance: config.checkpoint_distance,
                target_block_time: config.target_block_time,
                init_vdf_difficulty: config.init_vdf_difficulty,
                max_difficulty_adjustment: config.max_difficulty_adjustment,
                vdf_params: config.vdf_params,
            };

            Graph::genesis(dir, graph_config)
        };

        let engine = Arc::new(Self {
            transport,
            gossipsub,
            request_response: req_resp,
            gossip_topic: config.gossip_topic,
            graph: RwLock::new(graph),
            pending_atoms: DashMap::new(),
            atom_result_tx,
            heartbeat_interval: config.heartbeat_interval,
            path,
        });

        let engine_clone = engine.clone();
        tokio::spawn(async move { engine_clone.run(gossip_rx, atom_result_rx).await });

        Ok(engine)
    }

    async fn bootstrap(
        transport: &Transport,
        peers: Vec<(PeerId, Multiaddr)>,
        timeout: tokio::time::Duration,
        dir: &str,
        config: Config,
    ) -> Result<Graph<V>> {
        use bincode::{
            config,
            serde::{decode_from_slice, encode_to_vec},
        };

        debug_assert!(!peers.is_empty());

        let config = graph::Config {
            block_threshold: config.block_threshold,
            checkpoint_distance: config.checkpoint_distance,
            target_block_time: config.target_block_time,
            init_vdf_difficulty: config.init_vdf_difficulty,
            max_difficulty_adjustment: config.max_difficulty_adjustment,
            vdf_params: config.vdf_params,
        };

        let graph = Graph::new(dir, config)?;
        let epoch = graph.epoch();

        let msg = encode_to_vec(Request::Sync(epoch), config::standard()).unwrap();
        let req_resp = transport.request_response();
        let mut peers_set = HashSet::new();

        for (peer, addr) in &peers {
            transport.dial(*peer, addr.clone()).await?;
            req_resp.send_request(*peer, msg.clone()).await;
            peers_set.insert(*peer);
        }

        tokio::time::timeout(timeout, async {
            while let Some(msg) = req_resp.recv().await {
                let Message::Response { response, peer } = &msg else {
                    continue;
                };

                if !peers_set.contains(peer) {
                    continue;
                }

                let Ok((atoms, _)) =
                    decode_from_slice::<Vec<Atom>, _>(response, config::standard())
                else {
                    continue;
                };

                if atoms.is_empty() {
                    return graph;
                }

                let mut tmp = graph.clone();
                if tmp.import(atoms).is_ok() {
                    return tmp;
                }
            }

            panic!("Channel closed");
        })
        .await
        .map_err(|_| Error::BootstrapTimeout)
    }

    pub async fn propose(
        &self,
        code: u8,
        inputs: impl IntoIterator<Item = (Multihash, impl Into<Vec<u8>>)>,
        created: impl IntoIterator<Item = (impl Into<Vec<u8>>, impl Into<Vec<u8>>)>,
    ) -> Result<(), graph::Error> {
        let graph = self.graph.read().await;
        let cmd = graph.create_command(code, inputs, created, &self.transport.local_peer_id())?;
        let handle = graph.create_atom(Some(cmd));
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
        mut atom_result_rx: Receiver<Atom>,
    ) {
        let mut hb_interval = self.heartbeat_interval.map(tokio::time::interval);
        let req_resp = self.transport.request_response();

        loop {
            let mut gossip_msg = None;
            let mut req_resp_msg = None;
            let mut atom_result = None;
            let mut hb_tick = false;

            tokio::select! {
                Some(msg) = gossip_rx.recv() => {
                    gossip_msg = Some(msg);
                }
                Some(msg) = req_resp.recv() => {
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
                let handle = self.graph.read().await.create_atom(None);
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

        self.on_recv_atom(atom, Some(msg.id), msg.propagation_source)
            .await;
    }

    async fn on_recv_atom(&self, atom: Atom, msg_id: Option<MessageId>, peer: PeerId) {
        let hash = atom.hash();

        for hash in atom.atoms.iter().chain(&[atom.hash(), atom.parent]) {
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
                    Request::Sync(epoch) => self.handle_sync_request(epoch, channel).await,
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

    async fn handle_sync_request(&self, epoch: u32, channel: ResponseChannel<Vec<u8>>) {
        use bincode::{config, serde::encode_into_std_write};

        let self_epoch = self.graph.read().await.epoch();

        if epoch > self_epoch {
            return;
        }

        let mut buf = Vec::new();
        let mut cur = epoch;

        while cur < self_epoch {
            let name = format!("{cur}1");
            let file_path = self.path.join(&name);

            if !file_path.exists() {
                log::error!("Storage file {name} not found");
                return;
            }

            let Ok(mut file) = File::open(&file_path) else {
                log::error!("Failed to open storage file {name}");
                return;
            };

            if let Err(e) = file.read_to_end(&mut buf) {
                log::error!("Failed to read storage file {name}: {e}");
                return;
            }

            cur += 1;

            let name = format!("{cur}0");
            let file_path = self.path.join(&name);

            if !file_path.exists() {
                log::error!("Storage file {name} not found");
                return;
            }

            let Ok(mut file) = File::open(&file_path) else {
                log::error!("Failed to open storage file {name}");
                return;
            };

            if let Err(e) = file.read_to_end(&mut buf) {
                log::error!("Failed to read storage file {name}: {e}");
                return;
            }
        }

        let atoms = self.graph.read().await.current_atoms();

        atoms.iter().for_each(|a| {
            encode_into_std_write(a, &mut buf, config::standard()).unwrap();
        });

        if let Err(e) = self.request_response.send_response(channel, buf).await {
            log::error!("Failed to send response: {e}");
        }
    }

    async fn on_atom_ready(&self, atom: Atom) -> bool {
        let hash = atom.hash();
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

    pub async fn status(&self) -> Status {
        self.graph.read().await.status()
    }
}
