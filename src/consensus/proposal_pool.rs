use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use dashmap::DashSet;
use libp2p::PeerId;
use tokio::{task::JoinHandle, time::Duration};

use crate::{
    consensus::vrf_elector::{self, Proof, VrfElector},
    constants::HashArray,
    crypto::keypair::{PublicKey, SecretKey},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, Node},
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
}

pub struct Config {
    pub external_topic: String,
    pub internal_topic: String,
    pub num_members: u32,
    pub network_latency: Duration,
}

struct Context {
    input: Vec<u8>,
    handle: JoinHandle<()>,
    proof: Proof,
    total_stakes: u32,
    proposals: Arc<DashSet<HashArray>>,
}

pub struct ProposalPool {
    transport: Arc<Transport>,
    public_key: PublicKey,
    elector: Arc<VrfElector>,
    ctx: Option<Context>,
    config: Config,
}

impl ProposalPool {
    pub fn new(transport: Arc<Transport>, secret_key: SecretKey, config: Config) -> Self {
        let public_key = secret_key.to_public_key();
        let elector = VrfElector::new(secret_key);

        Self {
            transport,
            public_key,
            elector: Arc::new(elector),
            ctx: None,
            config,
        }
    }

    pub async fn start(&mut self, input: Vec<u8>, stake: u32, total_stakes: u32) -> Result<()> {
        let proof =
            match self
                .elector
                .generate(&input, stake, total_stakes, self.config.num_members)?
            {
                Some(proof) => proof,
                None => {
                    return Ok(());
                }
            };

        let proposals = Arc::new(DashSet::new());

        let handle = self.collect_proposals(proposals.clone()).await?;

        let ctx = Context {
            input,
            handle,
            proof,
            total_stakes,
            proposals,
        };

        self.ctx = Some(ctx);

        Ok(())
    }

    async fn collect_proposals(
        &mut self,
        proposals: Arc<DashSet<HashArray>>,
    ) -> Result<JoinHandle<()>> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.external_topic)
            .await?;

        let transport = self.transport.clone();

        Ok(tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let gossipsub::Payload::Proposal(hash) = msg.payload {
                    match Self::fetch_proposal(&transport, hash).await {
                        Ok(true) => {
                            proposals.insert(hash);
                        }
                        Ok(false) => {
                            continue;
                        }
                        Err(e) => {
                            log::error!("Failed to fetch proposal: {e}");
                            continue;
                        }
                    }
                }
            }
        }))
    }

    async fn fetch_proposal(transport: &Transport, hash: HashArray) -> Result<bool> {
        transport
            .get::<Node>(&hash)
            .await
            .map(|opt| opt.is_some())
            .map_err(Error::from)
    }

    pub async fn settle(&mut self, root: &Node) -> Result<HashSet<HashArray>> {
        let ctx = match self.ctx.take() {
            Some(ctx) => ctx,
            None => panic!("ProposalPool is not started"),
        };

        ctx.handle.abort();

        let proposals = Self::get_proposals(&ctx);

        let payload = gossipsub::Payload::ProposalSet {
            proposals: proposals.clone(),
            proof: ctx.proof.proof,
            public_key: self.public_key.clone(),
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        let proposals = self
            .collect_proposal_set(ctx.proof.times, proposals, root)
            .await?;

        Ok(proposals)
    }

    fn get_proposals(ctx: &Context) -> HashSet<HashArray> {
        Arc::try_unwrap(ctx.proposals.clone())
            .expect("Arc still has multiple owners")
            .into_iter()
            .collect()
    }

    async fn collect_proposal_set(
        &self,
        times: u32,
        set: HashSet<HashArray>,
        root: &Node,
    ) -> Result<HashSet<HashArray>> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let input = self
            .ctx
            .as_ref()
            .expect("ProposalPool is not started")
            .input
            .clone();

        let total_stakes = self
            .ctx
            .as_ref()
            .expect("ProposalPool is not started")
            .total_stakes;

        let mut total_times = times;
        let mut proposals: HashMap<HashArray, u32> = HashMap::new();

        set.into_iter().for_each(|hash| {
            proposals.insert(hash, times);
        });

        while let Some(msg) = rx.recv().await {
            if let gossipsub::Payload::ProposalSet {
                proposals: p,
                proof,
                public_key,
            } = msg.payload
            {
                let stakes = match self.get_stakes(&msg.source, root).await? {
                    Some(stakes) => stakes,
                    None => {
                        continue;
                    }
                };

                let times = VrfElector::calc_elected_times_with_proof(
                    &input,
                    stakes,
                    total_stakes,
                    self.config.num_members,
                    &proof,
                    &public_key,
                );

                p.into_iter().for_each(|hash| {
                    proposals
                        .entry(hash)
                        .and_modify(|count| *count += times)
                        .or_insert(times);
                });

                total_times += times;
            }
        }

        let mut accepted = HashSet::new();
        for (hash, count) in proposals {
            if count * 3 > total_times * 2 {
                accepted.insert(hash);
            }
        }

        Ok(accepted)
    }

    async fn get_stakes(&self, peer: &PeerId, root: &Node) -> Result<Option<u32>> {
        let peer = Self::vec_u8_to_key_array(peer.to_bytes());
        let Some(hash) = root.get(peer, &self.transport).await? else {
            return Ok(None);
        };

        Ok(self
            .transport
            .get::<Record>(&hash)
            .await?
            .map(|record| record.stakes))
    }

    fn vec_u8_to_key_array(vec: Vec<u8>) -> KeyArray {
        let mut result = KeyArray::default();

        result.iter_mut().enumerate().for_each(|(i, v)| {
            let high = vec[i * 2] as u16;
            let low = vec[i * 2 + 1] as u16;
            *v = (high << 8) | low;
        });

        result
    }
}
