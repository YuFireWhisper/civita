use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{
    constants::HashArray,
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, Node},
    },
    proposal::{
        collector::{self, Collector, Context},
        vrf_elector, Proposal,
    },
    resident::Record,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    VrfElector(#[from] vrf_elector::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),

    #[error("{0}")]
    Collector(#[from] collector::Error),

    #[error("{0}")]
    ProposalToVec(String),

    #[error("{0}")]
    ProposalSerialization(String),

    #[error("Insufficient stake for peer {0}")]
    InsufficientStake(PeerId),

    #[error("Invalid peer or proof for message from {0}")]
    InvalidPeerOrProof(PeerId),

    #[error("{0}")]
    Proposal(String),
}

pub struct Config {
    pub external_topic: String,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
#[derive(Hash)]
#[derive(Serialize, Deserialize)]
struct RecordKey {
    pub hash: HashArray,
    pub key: KeyArray,
    pub timestamp: u64,
}

#[derive(Clone)]
struct ProposalContext<P> {
    transport: Arc<Transport>,
    records: HashMap<RecordKey, Record>,
    root: Node,
    _marker: PhantomData<P>,
}

pub struct Pool<P: Proposal> {
    transport: Arc<Transport>,
    collector: Collector<ProposalContext<P>>,
    config: Config,
}

impl<P: Proposal> ProposalContext<P> {
    pub fn new(transport: Arc<Transport>, root: Node) -> Self {
        Self {
            transport,
            records: HashMap::new(),
            root,
            _marker: PhantomData,
        }
    }

    async fn add_proposal(&mut self, proposal_vec: &[u8]) -> Result<()> {
        let timestamp = Self::current_timestamp();

        let proposal =
            P::from_slice(proposal_vec).map_err(|e| Error::ProposalSerialization(e.to_string()))?;

        let resident_keys = proposal
            .impact()
            .map_err(|e| Error::Proposal(e.to_string()))?;
        let impacted_residents = self.get_impacted_residents(resident_keys.clone()).await?;

        let mut records: HashMap<_, _> =
            resident_keys.into_iter().zip(impacted_residents).collect();

        if !proposal
            .verify(&records)
            .map_err(|e| Error::Proposal(e.to_string()))?
        {
            log::warn!("Proposal verification failed");
            return Ok(());
        }

        proposal
            .apply(&mut records)
            .map_err(|e| Error::Proposal(e.to_string()))?;

        records.into_iter().for_each(|(key, record)| {
            let hash = Self::compute_hash(&record.to_vec());

            let key = RecordKey {
                hash,
                key: hash_to_key_array(key),
                timestamp,
            };

            self.records.insert(key, record);
        });

        Ok(())
    }

    async fn get_impacted_residents(&self, hashes: Vec<HashArray>) -> Result<Vec<Record>> {
        let keys: Vec<KeyArray> = hashes.into_iter().map(hash_to_key_array).collect();

        let hashes = self.root.batch_get(keys, &self.transport).await?;

        let futures = hashes
            .into_iter()
            .map(|hash_opt| async move {
                if let Some(hash) = hash_opt {
                    self.transport.get::<Record>(&hash).await
                } else {
                    Ok(Some(Record::default()))
                }
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(futures)
            .await
            .into_iter()
            .map(|res| match res {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Ok(Record::default()),
                Err(e) => Err(Error::from(e)),
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }

    fn compute_hash(data: &[u8]) -> HashArray {
        blake3::hash(data).into()
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time should not be before UNIX_EPOCH")
            .as_secs()
            / 60
    }
}

impl<P: Proposal> Pool<P> {
    pub fn new(transport: Arc<Transport>, config: Config) -> Self {
        Self {
            transport,
            collector: Collector::new(),
            config,
        }
    }

    pub async fn start(&mut self, root: Node) -> Result<()> {
        let ctx = ProposalContext::<P>::new(self.transport.clone(), root);
        let rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;
        self.collector.start(rx, ctx).await;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<Vec<(KeyArray, Record)>> {
        let ctx = self.collector.stop().await?;
        let mut entries: Vec<_> = ctx.records.into_iter().collect();

        entries.sort_by(|(key_a, _), (key_b, _)| {
            key_a
                .timestamp
                .cmp(&key_b.timestamp)
                .then(key_a.hash.cmp(&key_b.hash))
        });

        let records: Vec<_> = entries
            .into_iter()
            .map(|(key, record)| (key.key, record))
            .collect();

        Ok(records)
    }
}

pub fn hash_to_key_array(hash: HashArray) -> KeyArray {
    unsafe { std::mem::transmute(hash) }
}

pub fn key_array_to_hash(key: KeyArray) -> HashArray {
    unsafe { std::mem::transmute(key) }
}

#[async_trait::async_trait]
impl<P: Proposal> Context for ProposalContext<P> {
    async fn handle_message(&mut self, msg: gossipsub::Message) {
        if let gossipsub::Payload::Proposal(data) = msg.payload {
            if let Err(e) = self.add_proposal(&data).await {
                log::warn!("Failed to add proposal: {e}");
            }
        }
    }
}
