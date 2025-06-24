use std::{fmt::Display, sync::Arc};

use dashmap::DashMap;
use tokio::sync::oneshot;

use crate::{
    crypto::{traits::hasher::HashArray, Hasher},
    network::transport::behaviour::Behaviour,
};

pub mod message;
pub mod payload;
pub mod validated_store;

pub use message::Message;
pub use payload::Payload;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Put error: {0}")]
    Put(#[from] libp2p::kad::PutRecordError),

    #[error("Get error: {0}")]
    Get(#[from] libp2p::kad::GetRecordError),

    #[error("Waiting for Kademlia operation timed out after {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Oneshot error: {0}")]
    Oneshot(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Store error: {0}")]
    Store(#[from] libp2p::kad::store::Error),

    #[error("{0}")]
    ConvertFromPayload(String),

    #[error("No found payload for the given key")]
    NotFound,

    #[error("{0}")]
    ConvertFromVec(String),
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

enum WaitingQuery {
    Put(oneshot::Sender<Result<()>>),
    Get(oneshot::Sender<Result<Option<libp2p::kad::PeerRecord>>>),
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
    waiting_queries: DashMap<libp2p::kad::QueryId, WaitingQuery>,
    config: Config,
}

impl Kad {
    pub fn new(
        swarm: Arc<tokio::sync::Mutex<libp2p::swarm::Swarm<Behaviour>>>,
        config: Config,
    ) -> Self {
        Self {
            swarm,
            waiting_queries: DashMap::new(),
            config,
        }
    }

    pub fn handle_event(&self, event: libp2p::kad::Event) {
        match event {
            libp2p::kad::Event::OutboundQueryProgressed { id, result, .. } => {
                self.handle_outbound(id, result);
            }
            _ => log::trace!("Ignoring Kademlia event: {event:?}"),
        }
    }

    fn handle_outbound(&self, id: libp2p::kad::QueryId, result: libp2p::kad::QueryResult) {
        use libp2p::kad::{GetRecordOk, QueryResult};

        match result {
            QueryResult::PutRecord(result) => {
                let Some((_, sender)) = self.waiting_queries.remove(&id) else {
                    return;
                };

                let result = match result {
                    Ok(_) => Ok(()),
                    Err(err) => Err(Error::Put(err)),
                };

                let WaitingQuery::Put(sender) = sender else {
                    panic!("Expected a Put query result, but got a different type");
                };

                if let Err(err) = sender.send(result) {
                    log::warn!("Failed to send put record result, receiver dropped: {err:?}");
                }
            }
            QueryResult::GetRecord(result) => {
                let Some((_, sender)) = self.waiting_queries.remove(&id) else {
                    return;
                };

                let result = match result {
                    Ok(GetRecordOk::FoundRecord(record)) => Ok(Some(record)),
                    Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => Ok(None),
                    Err(err) => Err(Error::Get(err)),
                };

                let WaitingQuery::Get(sender) = sender else {
                    panic!("Expected a Get query result, but got a different type");
                };

                if let Err(err) = sender.send(result) {
                    log::warn!("Failed to send get record result, receiver dropped: {err:?}");
                }
            }
            _ => log::debug!("Received unhandled query result: {result:?}"),
        }
    }

    pub async fn put<H: Hasher>(&self, record: Vec<u8>) -> Result<()> {
        let key = H::hash(&record);
        let key = libp2p::kad::RecordKey::new(&key);

        let record = libp2p::kad::Record::new(key, record);

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm
            .behaviour_mut()
            .kad_mut()
            .put_record(record, self.config.quorum)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Put(tx));

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await??
    }

    pub async fn get_or_error<T: TryFrom<Vec<u8>, Error: Display>, H: Hasher>(
        &self,
        key: &HashArray<H>,
    ) -> Result<T> {
        self.get::<T, H>(key).await?.ok_or(Error::NotFound)
    }

    pub async fn get<T: TryFrom<Vec<u8>, Error: Display>, H: Hasher>(
        &self,
        key: &HashArray<H>,
    ) -> Result<Option<T>> {
        let mut swarm = self.swarm.lock().await;
        let key = libp2p::kad::RecordKey::new(key);

        let query_id = swarm.behaviour_mut().kad_mut().get_record(key);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Get(tx));

        let peer_record_opt =
            tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await???;

        match peer_record_opt {
            Some(peer_record) => {
                let t = T::try_from(peer_record.record.value)
                    .map_err(|e| Error::ConvertFromVec(e.to_string()))?;
                Ok(Some(t))
            }
            None => Ok(None),
        }
    }
}
