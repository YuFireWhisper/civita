use std::sync::Arc;

use dashmap::DashMap;

use crate::{crypto::tss::Signature, network::transport::libp2p_transport::behaviour::Behaviour};

pub mod key;
pub mod message;
pub mod payload;
pub mod validated_store;

pub use key::Key;
pub use message::Message;
pub use payload::Payload;

pub const PEER_INFO_KEY: &str = "peer";

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Put error: {0}")]
    Put(#[from] libp2p::kad::PutRecordError),

    #[error("Get error: {0}")]
    Get(#[from] libp2p::kad::GetRecordError),

    #[error("Invalid payload type for Kademlia key generation")]
    InvalidPayloadType,

    #[error("Waiting for Kademlia operation timed out after {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("{0}")]
    Message(#[from] message::Error),

    #[error("Oneshot error: {0}")]
    Oneshot(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Store error: {0}")]
    Store(#[from] libp2p::kad::store::Error),

    #[error("{0}")]
    Key(#[from] key::Error),

    #[error("Payload error: {0}")]
    Payload(#[from] payload::Error),
}

#[derive(Debug)]
pub struct Config {
    pub wait_for_kad_result_timeout: tokio::time::Duration,
    pub quorum: libp2p::kad::Quorum,
}

#[derive(Debug)]
#[derive(Default)]
pub struct ConfigBuilder {
    wait_for_kad_result_timeout: Option<tokio::time::Duration>,
    quorum: Option<libp2p::kad::Quorum>,
}

impl ConfigBuilder {
    const DEFAULT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(5);
    const DEFAULT_QUORUM: libp2p::kad::Quorum = libp2p::kad::Quorum::All;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn wait_for_kad_result_timeout(mut self, timeout: tokio::time::Duration) -> Self {
        self.wait_for_kad_result_timeout = Some(timeout);
        self
    }

    pub fn with_quorum(mut self, quorum: libp2p::kad::Quorum) -> Self {
        self.quorum = Some(quorum);
        self
    }

    pub fn build(self) -> Config {
        Config {
            wait_for_kad_result_timeout: self
                .wait_for_kad_result_timeout
                .unwrap_or(Self::DEFAULT_TIMEOUT),
            quorum: self.quorum.unwrap_or(Self::DEFAULT_QUORUM),
        }
    }
}

pub struct Kad {
    swarm: Arc<tokio::sync::Mutex<libp2p::swarm::Swarm<Behaviour>>>,
    waiting_put_queries: DashMap<libp2p::kad::QueryId, tokio::sync::oneshot::Sender<Result<()>>>,
    waiting_get_queries: DashMap<
        libp2p::kad::QueryId,
        tokio::sync::oneshot::Sender<Result<Option<libp2p::kad::PeerRecord>>>,
    >,
    config: Config,
}

impl Kad {
    pub fn new(
        swarm: Arc<tokio::sync::Mutex<libp2p::swarm::Swarm<Behaviour>>>,
        config: Config,
    ) -> Self {
        Self {
            swarm,
            waiting_put_queries: DashMap::new(),
            waiting_get_queries: DashMap::new(),
            config,
        }
    }

    pub fn handle_event(&self, event: libp2p::kad::Event) {
        match event {
            libp2p::kad::Event::OutboundQueryProgressed { id, result, .. } => {
                self.handle_outbound(id, result);
            }
            _ => log::trace!("Ignoring Kademlia event: {:?}", event),
        }
    }

    fn handle_outbound(&self, id: libp2p::kad::QueryId, result: libp2p::kad::QueryResult) {
        use libp2p::kad::{GetRecordOk, QueryResult};

        match result {
            QueryResult::PutRecord(result) => {
                if let Some((_, sender)) = self.waiting_put_queries.remove(&id) {
                    let send_result = match result {
                        Ok(_) => sender.send(Ok(())),
                        Err(err) => sender.send(Err(Error::Put(err))),
                    };

                    if send_result.is_err() {
                        log::warn!("Failed to send put record result, receiver dropped");
                    }
                }
            }
            QueryResult::GetRecord(result) => {
                if let Some((_, sender)) = self.waiting_get_queries.remove(&id) {
                    let response = match result {
                        Ok(GetRecordOk::FoundRecord(record)) => Ok(Some(record)),
                        Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => Ok(None),
                        Err(err) => Err(Error::Get(err)),
                    };

                    if sender.send(response).is_err() {
                        log::warn!("Failed to send get record result, receiver dropped");
                    }
                }
            }
            _ => log::debug!("Received unhandled query result: {:?}", result),
        }
    }

    pub async fn put(&self, key: Key, payload: Payload, signature: Signature) -> Result<()> {
        let key = key.to_storage_key()?;
        let record_value = Message::new(payload, signature).to_vec()?;
        let record = libp2p::kad::Record::new(key, record_value);

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm
            .behaviour_mut()
            .kad_mut()
            .put_record(record, self.config.quorum)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_put_queries.insert(query_id, tx);

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await??
    }

    pub async fn get(&self, key: Key) -> Result<Option<Payload>> {
        let mut swarm = self.swarm.lock().await;
        let key = key.to_storage_key()?;
        let query_id = swarm.behaviour_mut().kad_mut().get_record(key);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_get_queries.insert(query_id, tx);

        let peer_record_opt =
            tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await???;
        match peer_record_opt {
            Some(peer_record) => {
                let payload = Payload::try_from(peer_record.record)?;
                Ok(Some(payload))
            }
            None => Ok(None),
        }
    }
}
