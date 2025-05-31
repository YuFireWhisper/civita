use std::{collections::HashMap, marker::PhantomData, sync::Arc};

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

#[derive(Clone)]
#[derive(Debug)]
pub struct Config {
    pub external_topic: String,
    pub num_proposals_per_batch: usize,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub struct RecordBatch {
    pub records: Vec<(KeyArray, Record)>,
    pub total_stakes_impact: i32,
}

#[derive(Clone)]
struct ProposalContext<P> {
    transport: Arc<Transport>,
    batches: Vec<RecordBatch>,
    root: Node,
    num_proposals_per_batch: usize,
    _marker: PhantomData<P>,
}

pub struct Pool<P: Proposal> {
    transport: Arc<Transport>,
    collector: Collector<ProposalContext<P>>,
    config: Config,
}

impl<P: Proposal> ProposalContext<P> {
    pub fn new(
        transport: Arc<Transport>,
        root: Node,
        batches: Vec<RecordBatch>,
        num_proposals_per_batch: usize,
    ) -> Self {
        Self {
            transport,
            batches,
            root,
            num_proposals_per_batch,
            _marker: PhantomData,
        }
    }

    async fn add_proposal(&mut self, slice: &[u8]) -> Result<()> {
        let proposal =
            P::from_slice(slice).map_err(|e| Error::ProposalSerialization(e.to_string()))?;

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

        let impact_stakes = proposal
            .impact_stakes()
            .map_err(|e| Error::Proposal(e.to_string()))?;

        if self.batches.is_empty()
            || self.batches.last().unwrap().records.len() >= self.num_proposals_per_batch
        {
            self.batches.push(RecordBatch::default());
        }

        let last_batch = self.batches.last_mut().unwrap();

        last_batch.total_stakes_impact += impact_stakes;
        last_batch
            .records
            .extend(records.into_iter().map(|(k, v)| (hash_to_key_array(k), v)));

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
}

impl<P: Proposal> Pool<P> {
    pub fn new(transport: Arc<Transport>, config: Config) -> Self {
        Self {
            transport,
            collector: Collector::new(),
            config,
        }
    }

    pub async fn start(&self, root: Node, per_batches: Vec<RecordBatch>) -> Result<()> {
        let ctx = ProposalContext::<P>::new(
            self.transport.clone(),
            root,
            per_batches,
            self.config.num_proposals_per_batch,
        );
        let rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;
        self.collector.start(rx, ctx).await;
        Ok(())
    }

    pub async fn stop(&self) -> Result<Vec<RecordBatch>> {
        let ctx = self.collector.stop().await?;
        Ok(ctx.batches)
    }
}

pub fn hash_to_key_array(hash: HashArray) -> KeyArray {
    unsafe { std::mem::transmute(hash) }
}

pub fn key_to_hash_array(key: KeyArray) -> HashArray {
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
