use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use libp2p::{
    kad::{QueryId, QueryResult, Quorum, Record, RecordKey},
    Swarm,
};
use tokio::{
    sync::{oneshot, Mutex},
    time::Duration,
};

use crate::{
    crypto::Multihash,
    network::behaviour::Behaviour,
    traits::{serializable, Serializable},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Put(#[from] libp2p::kad::PutRecordError),

    #[error("{0}")]
    Get(#[from] libp2p::kad::GetRecordError),

    #[error("Waiting for Kademlia operation timed out after {0:?}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("{0}")]
    Oneshot(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    Store(#[from] libp2p::kad::store::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),
}

#[derive(Debug)]
pub struct Config {
    pub wait_for_kad_result_timeout: Duration,
    pub quorum: Quorum,
}

enum WaitingQuery {
    Put(oneshot::Sender<Result<()>>),
    Get(oneshot::Sender<Result<Option<libp2p::kad::PeerRecord>>>),
}

#[derive()]
pub struct Storage {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    waiting_queries: DashMap<QueryId, WaitingQuery>,
    config: Config,
}

impl Storage {
    pub fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>, config: Config) -> Self {
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

    fn handle_outbound(&self, id: QueryId, result: QueryResult) {
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

    pub async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serializable + Sync + Send + 'static,
    {
        let key = RecordKey::new(&key.to_bytes());

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm.behaviour_mut().kad_mut().get_record(key);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Get(tx));

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx)
            .await???
            .map(|peer_record| T::from_slice(&peer_record.record.value).map_err(Error::from))
            .transpose()
    }

    pub async fn put<T>(&self, key: Multihash, value: T) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static,
    {
        let key = RecordKey::new(&key.to_bytes());
        let record = Record::new(key, value.to_vec());

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm
            .behaviour_mut()
            .kad_mut()
            .put_record(record, self.config.quorum)
            .map_err(Error::from)?;

        let (tx, rx) = oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Put(tx));

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await???;

        Ok(())
    }

    pub async fn put_batch<T, I>(&self, items: I) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static,
        I: IntoIterator<Item = (Multihash, T)>,
    {
        let items: Vec<_> = items.into_iter().collect();

        if items.is_empty() {
            return Ok(());
        }

        let mut records = Vec::new();
        let mut query_senders = HashMap::new();

        for (hash, value) in items {
            let key = libp2p::kad::RecordKey::new(&hash.to_bytes());
            let record = libp2p::kad::Record::new(key, value.to_vec());
            records.push(record);
        }

        let mut swarm = self.swarm.lock().await;

        for record in records {
            let query_id = swarm
                .behaviour_mut()
                .kad_mut()
                .put_record(record, self.config.quorum)
                .map_err(Error::from)?;

            let (tx, rx) = oneshot::channel();
            query_senders.insert(query_id, rx);
            self.waiting_queries.insert(query_id, WaitingQuery::Put(tx));
        }

        drop(swarm);

        let futures: Vec<_> = query_senders
            .into_values()
            .map(|rx| tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx))
            .collect();

        let results = futures::future::join_all(futures).await;

        for result in results {
            result???;
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wait_for_kad_result_timeout: Duration::from_secs(10),
            quorum: libp2p::kad::Quorum::One,
        }
    }
}
