use std::{collections::HashMap, sync::Arc};

use dashmap::DashMap;
use tokio::{sync::oneshot, time::Duration};

use crate::{
    crypto::Multihash,
    network::{
        traits::{storage::Error, Storage},
        transport::behaviour::Behaviour,
    },
    traits::Serializable,
};

pub mod validated_store;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct Config {
    pub wait_for_kad_result_timeout: tokio::time::Duration,
    pub quorum: libp2p::kad::Quorum,
}

enum WaitingQuery {
    Put(oneshot::Sender<Result<()>>),
    Get(oneshot::Sender<Result<Option<libp2p::kad::PeerRecord>>>),
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wait_for_kad_result_timeout: Duration::from_secs(10),
            quorum: libp2p::kad::Quorum::Majority,
        }
    }
}

#[async_trait::async_trait]
impl Storage for Arc<Kad> {
    async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
    where
        T: Serializable + Sync + Send + 'static,
    {
        let key = libp2p::kad::RecordKey::new(&key.to_bytes());

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm.behaviour_mut().kad_mut().get_record(key);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Get(tx));

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx)
            .await???
            .map(|peer_record| T::from_slice(&peer_record.record.value).map_err(Error::from))
            .transpose()
    }

    async fn put<T>(&mut self, key: Multihash, value: T) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static,
    {
        let key = libp2p::kad::RecordKey::new(&key.to_bytes());
        let record = libp2p::kad::Record::new(key, value.to_vec()?);

        let mut swarm = self.swarm.lock().await;
        let query_id = swarm
            .behaviour_mut()
            .kad_mut()
            .put_record(record, self.config.quorum)
            .map_err(Error::from)?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiting_queries.insert(query_id, WaitingQuery::Put(tx));

        tokio::time::timeout(self.config.wait_for_kad_result_timeout, rx).await???;

        Ok(())
    }

    async fn put_batch<T, I>(&mut self, items: I) -> Result<()>
    where
        T: Serializable + Sync + Send + 'static,
        I: IntoIterator<Item = (Multihash, T)> + Send + Sync,
    {
        let items: Vec<_> = items.into_iter().collect();

        if items.is_empty() {
            return Ok(());
        }

        let mut records = Vec::new();
        let mut query_senders = HashMap::new();

        for (hash, value) in items {
            let key = libp2p::kad::RecordKey::new(&hash.to_bytes());
            let record = libp2p::kad::Record::new(key, value.to_vec()?);
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
//
// #[async_trait::async_trait]
// impl Storage for Arc<Kad> {
//     async fn get<T>(&self, key: &Multihash) -> Result<Option<T>>
//     where
//         T: Serializable + Sync + Send + 'static,
//     {
//         self.get(key).await
//     }
//
//     async fn put<T>(&mut self, key: Multihash, value: T) -> Result<()>
//     where
//         T: Serializable + Sync + Send + 'static,
//     {
//         self.put(key, value).await
//     }
//
//     async fn put_batch<T, I>(&mut self, items: I) -> Result<()>
//     where
//         T: Serializable + Sync + Send + 'static,
//         I: IntoIterator<Item = (Multihash, T)> + Send + Sync,
//     {
//         self.put_batch(items).await
//     }
// }
