use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use dashmap::{mapref::one::RefMut, DashMap};
use tokio::sync::{
    mpsc::{Receiver as TokioReceiver, Sender as TokioSender},
    oneshot::Sender as TokioOneShotSender,
};

use crate::{
    crypto::{
        index_map::IndexedMap,
        primitives::{
            algebra::{self, Point, Scalar},
            threshold,
        },
    },
    network::transport::{libp2p_transport::protocols::gossipsub, Transport},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),

    #[error("Send Action Error: {0}")]
    SendAction(String),

    #[error("Channel Closed: {0}")]
    ChannelClosed(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    Algebra(#[from] algebra::Error),
}

#[derive(Debug)]
enum Command {
    Query {
        id: SessionId,
        immediate_return: bool,
        callback: TokioOneShotSender<CollectionResult>,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum CollectionResult {
    Success(HashMap<libp2p::PeerId, Scalar>),
    Failure(HashSet<libp2p::PeerId>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Hash)]
#[derive(PartialEq, Eq)]
enum SessionId {
    NonceShare(Vec<u8>),
    SignatureShare(Vec<u8>),
}

#[derive(Debug)]
struct Session {
    shares: HashMap<libp2p::PeerId, Scalar>,
    pending_peers: HashSet<libp2p::PeerId>,
    invalid_peers: HashSet<libp2p::PeerId>,
    global_comms: Vec<Point>,
    completed: bool,
    threshold: u16,
    callback: Option<TokioOneShotSender<CollectionResult>>,
}

#[derive(Debug)]
#[derive(Default)]
struct Context {
    session: DashMap<SessionId, Session>,
    threshold: u16,
    global_comms: Vec<Point>,
    peers_index: IndexedMap<libp2p::PeerId, ()>,
}

#[derive(Debug)]
pub struct Config {
    pub threshold_counter: threshold::Counter,
    pub topic: String,
    pub timeout: tokio::time::Duration,
}

pub struct Collector<T: Transport + 'static> {
    transport: Arc<T>,
    action_tx: Option<TokioSender<Command>>,
    config: Config,
}

impl Session {
    pub fn new(
        peers: impl Iterator<Item = libp2p::PeerId>,
        global_comms: Vec<Point>,
        threshold: u16,
    ) -> Self {
        Self {
            shares: HashMap::new(),
            pending_peers: peers.collect(),
            invalid_peers: HashSet::new(),
            global_comms,
            completed: false,
            threshold,
            callback: None,
        }
    }

    pub fn add_share(&mut self, peer_id: libp2p::PeerId, peer_index: u16, share: Scalar) {
        if self.completed || self.invalid_peers.contains(&peer_id) {
            return;
        }

        if self.pending_peers.remove(&peer_id) {
            if !self.verify_share(peer_index, &share) {
                self.invalid_peers.insert(peer_id);
                log::warn!("Invalid nonce share from peer: {:?}", peer_id);
            } else {
                self.shares.insert(peer_id, share);
                self.try_complete();
            }
        }
    }

    fn verify_share(&self, peer_index: u16, share: &Scalar) -> bool {
        share.verify(peer_index, &self.global_comms).is_ok()
    }

    fn try_complete(&mut self) {
        if !self.has_threshold_reached() || self.completed {
            return;
        }

        if let Some(callback) = self.callback.take() {
            let output = CollectionResult::Success(self.shares.to_owned());
            if let Err(e) = callback.send(output) {
                log::warn!("Failed to send nonce shares: {:?}", e);
            }
            self.completed = true;
        }
    }

    fn has_threshold_reached(&self) -> bool {
        self.shares.len() >= self.threshold as usize
    }

    pub fn set_callback(&mut self, callback: TokioOneShotSender<CollectionResult>) {
        if self.completed {
            return;
        }

        self.callback = Some(callback);
        self.try_complete();
    }

    pub fn is_completed(&self) -> bool {
        self.completed
    }

    pub fn force_completion(&mut self, callback: TokioOneShotSender<CollectionResult>) {
        if self.completed {
            return;
        }

        if self.has_threshold_reached() {
            let result = CollectionResult::Success(self.shares.clone());
            if let Err(e) = callback.send(result) {
                log::warn!("Failed to send collection result: {:?}", e);
            }
        } else {
            self.invalid_peers.extend(self.pending_peers.iter());
            let result = CollectionResult::Failure(self.invalid_peers.clone());
            if let Err(e) = callback.send(result) {
                log::warn!("Failed to send collection result: {:?}", e);
            }
        }

        self.completed = true;
    }
}

impl Context {
    pub fn new(threshold: u16, partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>) -> Self {
        let (global_comms, peers_index) =
            Self::calculate_global_comms_and_convert_to_set(partial_pks)
                .expect("Failed to calculate global commitments");

        Self {
            session: DashMap::new(),
            threshold,
            global_comms,
            peers_index,
        }
    }

    fn calculate_global_comms_and_convert_to_set(
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<(Vec<Point>, IndexedMap<libp2p::PeerId, ()>)> {
        let mut set = IndexedMap::new();

        let len = partial_pks
            .values()
            .next()
            .expect("Partial PKs should not empty")
            .len();
        let scheme = partial_pks
            .values()
            .next()
            .expect("Partial PKs should not empty")
            .first()
            .expect("Partial PKs should not empty")
            .scheme();
        let mut global_comms = vec![Point::zero(scheme); len];

        for (peer_id, pks) in partial_pks.into_iter() {
            for (i, pk) in pks.iter().enumerate() {
                global_comms[i] = global_comms[i].add(pk)?;
            }

            set.insert(peer_id, ());
        }

        Ok((global_comms, set))
    }

    pub fn add_share(&self, session_id: SessionId, peer_id: libp2p::PeerId, share: Scalar) {
        if !self.peers_index.contains_key(&peer_id) {
            return;
        }

        let index = self.get_index_or_unwrap(&peer_id);
        let mut session = self.get_or_create_session(session_id);
        session.add_share(peer_id, index, share);
    }

    fn get_or_create_session(&self, id: SessionId) -> RefMut<'_, SessionId, Session> {
        self.session.entry(id).or_insert_with(|| {
            let peers = self.peers_index.keys().cloned();
            Session::new(peers, self.global_comms.clone(), self.threshold)
        })
    }

    fn get_index_or_unwrap(&self, peer_id: &libp2p::PeerId) -> u16 {
        self.peers_index
            .get_index(peer_id)
            .expect("Peer ID in the peers index")
    }

    pub fn register_callback(&self, id: SessionId, callback: TokioOneShotSender<CollectionResult>) {
        let mut session = self.get_or_create_session(id);
        session.set_callback(callback);
    }

    pub fn force_completion(&self, id: SessionId, callback: TokioOneShotSender<CollectionResult>) {
        let mut session = self.get_or_create_session(id);
        session.force_completion(callback);
    }

    pub fn cleanup_completed_sessions(&self) {
        let completed_keys: Vec<SessionId> = self
            .session
            .iter()
            .filter_map(|entry| {
                if entry.is_completed() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        for key in completed_keys {
            self.session.remove(&key);
        }
    }
}

impl<T: Transport + 'static> Collector<T> {
    pub fn new(transport: Arc<T>, config: Config) -> Self {
        Self {
            transport,
            action_tx: None,
            config,
        }
    }

    pub async fn start(
        &mut self,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<()> {
        let topic_rx = self
            .transport
            .listen_on_topic(&self.config.topic)
            .await
            .map_err(|e| Error::Transport(e.to_string()))?;

        let (action_tx, action_rx) = tokio::sync::mpsc::channel(100);
        self.action_tx = Some(action_tx);

        let threshold = self.config.threshold_counter.call(partial_pks.len()) - 1; // Exclude self
        let ctx = Context::new(threshold, partial_pks);

        tokio::spawn(async move {
            Self::run(ctx, topic_rx, action_rx).await;
        });

        Ok(())
    }

    async fn run(
        ctx: Context,
        mut topic_rx: TokioReceiver<gossipsub::Message>,
        mut action_rx: TokioReceiver<Command>,
    ) {
        const CLEANUP_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);

        let mut cleanup_timer = tokio::time::interval(CLEANUP_INTERVAL);

        loop {
            tokio::select! {
                Some(message) = topic_rx.recv() => {
                    Self::process_message(&ctx, message);
                }
                Some(action) = action_rx.recv() => {
                    match action {
                        Command::Query { id, immediate_return, callback } => {
                            Self::process_query_nonce_shares(&ctx, id, immediate_return, callback);
                        }
                        Command::Shutdown => {
                            log::info!("Shutting down collector");
                            break;
                        }
                    }
                }
                _ = cleanup_timer.tick() => {
                    ctx.cleanup_completed_sessions();
                }
            }
        }

        log::info!("Collector stopped");
    }

    fn process_message(ctx: &Context, message: gossipsub::Message) {
        if let gossipsub::Payload::TssNonceShare { id, share } = message.payload {
            let id = SessionId::NonceShare(id);
            let peer_id = message.source;
            ctx.add_share(id, peer_id, share);
        }
    }

    fn process_query_nonce_shares(
        ctx: &Context,
        id: SessionId,
        immediate_return: bool,
        callback: TokioOneShotSender<CollectionResult>,
    ) {
        if immediate_return {
            ctx.force_completion(id, callback);
        } else {
            ctx.register_callback(id, callback);
        }
    }

    pub async fn stop(&mut self) {
        if let Some(action_tx) = self.action_tx.take() {
            let _ = action_tx.send(Command::Shutdown).await;
        }
    }

    pub async fn query_nonce_shares(&self, id: Vec<u8>) -> Result<CollectionResult> {
        let id = SessionId::NonceShare(id);
        if let Some(result) = self.query_with_timeout(id.clone()).await? {
            Ok(result)
        } else {
            return Ok(self.query_with_force(id).await);
        }
    }

    async fn query_with_timeout(&self, id: SessionId) -> Result<Option<CollectionResult>> {
        let action_tx = self.action_tx.as_ref().expect("Collector is not started");

        let (callback_tx, callback_rx) = tokio::sync::oneshot::channel();
        let command = Command::Query {
            id: id.clone(),
            immediate_return: false,
            callback: callback_tx,
        };
        action_tx
            .send(command)
            .await
            .expect("Failed to send command");

        match tokio::time::timeout(self.config.timeout, callback_rx).await {
            // Result<Result<CollectionResult, RecvError>, Elapsed>
            Ok(result) => Ok(Some(result?)),
            Err(e) => {
                log::warn!("Timeout while waiting for nonce shares: {:?}", e);
                Ok(None)
            }
        }
    }

    async fn query_with_force(&self, id: SessionId) -> CollectionResult {
        let action_tx = self.action_tx.as_ref().expect("Collector is not started");

        let (callback_tx, callback_rx) = tokio::sync::oneshot::channel();
        let command = Command::Query {
            id: id.clone(),
            immediate_return: true,
            callback: callback_tx,
        };
        action_tx
            .send(command)
            .await
            .expect("Failed to send command");

        match callback_rx.await {
            Ok(result) => result,
            Err(e) => {
                panic!("Failed to receive callback: {:?}", e);
            }
        }
    }

    pub async fn query_signature_share(&self, id: Vec<u8>) -> Result<CollectionResult> {
        let id = SessionId::SignatureShare(id);
        if let Some(result) = self.query_with_timeout(id.clone()).await? {
            Ok(result)
        } else {
            return Ok(self.query_with_force(id).await);
        }
    }
}
