use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    constants::HashArray,
    crypto::keypair::{self, PublicKey, ResidentSignature, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, MerkleDag, Node},
    },
    proposal::{
        collector::{self, Collector, Context},
        pool::{hash_to_key_array, CollectionResult},
        vrf_elector::VrfElector,
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
    MarkleDag(#[from] merkle_dag::Error),

    #[error("{0}")]
    Node(#[from] merkle_dag::node::Error),

    #[error("{0}")]
    Keypair(#[from] keypair::Error),

    #[error("Invalid peer or proof for message from {0}")]
    InvalidPeerOrProof(PeerId),

    #[error("Insufficient stake for peer {0}")]
    InsufficientStake(PeerId),

    #[error("Consensus failed")]
    ConsensusFailed,

    #[error("{0}")]
    Collector(#[from] collector::Error),
}

pub struct Config {
    pub batch_size: usize,
    pub per_time_max_records: usize,
    pub network_latency: Duration,
    pub internal_topic: String,
    pub external_topic: String,
}

#[derive(Debug)]
struct MemberInfo {
    public_key: PublicKey,
    proof: VrfProof,
    signature: ResidentSignature,
}

#[derive(Debug)]
struct VoteContext {
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    votes: HashMap<Vec<u8>, (Vec<MemberInfo>, u32)>,
    voted: HashSet<PeerId>,
    input: Vec<u8>,
    total_stakes: u32,
    total_times: u32,
    root: Node,
    final_node: Option<Vec<u8>>,
}

pub struct Publisher {
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    merkle_dag: MerkleDag,
    config: Config,
}

impl MemberInfo {
    fn to_hash_map<I>(iter: I) -> HashMap<PublicKey, (VrfProof, ResidentSignature)>
    where
        I: IntoIterator<Item = Self>,
    {
        iter.into_iter()
            .map(|info| (info.public_key, (info.proof, info.signature)))
            .collect()
    }
}

impl VoteContext {
    fn verify_source(
        &self,
        source: &PeerId,
        public_key: &PublicKey,
        proof: &VrfProof,
    ) -> Result<()> {
        if &public_key.to_peer_id() != source {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        if !public_key.verify_proof(&self.input, proof) {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        if self.voted.contains(source) {
            return Err(Error::InvalidPeerOrProof(*source));
        }

        Ok(())
    }

    async fn get_voting_times(&self, peer_id: PeerId, proof: &VrfProof) -> Result<u32> {
        let stakes = self
            .get_peer_stakes(&peer_id)
            .await?
            .ok_or(Error::InsufficientStake(peer_id))?;

        let times = self
            .elector
            .calc_elected_times(stakes, self.total_stakes, &proof.output());

        if times == 0 {
            return Err(Error::InsufficientStake(peer_id));
        }

        Ok(times)
    }

    async fn get_peer_stakes(&self, peer_id: &PeerId) -> Result<Option<u32>> {
        let hash: HashArray = peer_id.to_bytes().try_into().unwrap();

        let key = hash_to_key_array(hash);
        let hash = self.root.get(key, &self.transport).await?;

        match hash {
            Some(hash) => Ok(self.transport.get::<Record>(&hash).await?.map(|r| r.stakes)),
            None => Ok(None),
        }
    }
}

impl Publisher {
    pub fn new(transport: Arc<Transport>, elector: Arc<VrfElector>, config: Config) -> Self {
        let merkle_dag = MerkleDag::new(transport.clone(), config.batch_size);

        Self {
            transport,
            elector,
            merkle_dag,
            config,
        }
    }

    pub async fn generate_new_root(
        &mut self,
        root: Node,
        mut result: CollectionResult,
    ) -> Result<()> {
        let length = std::cmp::min(result.records.len(), self.config.per_time_max_records);
        let mut pending = std::mem::take(&mut result.records);
        let next = pending.split_off(length);

        let pairs: Vec<(KeyArray, HashArray)> =
            pending.iter().map(|(key, _)| (key.key, key.hash)).collect();

        self.merkle_dag.change_root(root);
        self.merkle_dag.batch_insert(pairs).await?;

        let (final_node, proofs) = self.collect_votes(self.merkle_dag.root(), result).await?;

        let payload = gossipsub::Payload::ProposalProcessingComplete {
            final_node,
            processed: pending
                .iter()
                .map(|(key, _)| key.hash)
                .collect::<HashSet<_>>(),
            next: next.into_iter().collect::<HashMap<_, _>>(),
            proofs,
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_votes(
        &self,
        root: &Node,
        result: CollectionResult,
    ) -> Result<(Vec<u8>, HashMap<PublicKey, (VrfProof, ResidentSignature)>)> {
        let rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let root_bytes = root.to_vec().await;
        let proof = result.proof;
        let public_key = result.public_key;
        let signature = self.elector.secret_key().sign(&root_bytes)?;

        let payload = gossipsub::Payload::ConsensusMerkleRoot {
            root_bytes,
            proof,
            public_key,
            signature,
        };

        self.transport
            .publish(&self.config.internal_topic, payload)
            .await?;

        let mut collector = Collector::<VoteContext>::new();

        let vote_context = VoteContext {
            transport: self.transport.clone(),
            elector: self.elector.clone(),
            votes: HashMap::new(),
            voted: HashSet::new(),
            input: result.input.clone(),
            total_stakes: result.total_stakes,
            total_times: result.total_times,
            root: root.clone(),
            final_node: None,
        };

        collector.start(rx, vote_context).await;

        let mut ctx = collector
            .wait_for_stop(self.config.network_latency)
            .await
            .ok_or(Error::ConsensusFailed)??;

        let final_node = ctx.final_node.unwrap();

        let proofs = ctx
            .votes
            .remove(&final_node)
            .expect("Final node should have votes");

        let iter = proofs.0.into_iter();
        let proofs = MemberInfo::to_hash_map(iter);

        Ok((final_node, proofs))
    }
}

#[async_trait::async_trait]
impl Context for VoteContext {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        if let gossipsub::Payload::ConsensusMerkleRoot {
            root_bytes,
            proof,
            public_key,
            signature,
        } = msg.payload
        {
            if let Err(e) = self.verify_source(&msg.source, &public_key, &proof) {
                log::warn!("{e}");
                return false;
            }

            if !public_key.verify_signature(&root_bytes, &signature) {
                log::warn!("Invalid signature for message from {}", msg.source);
                return false;
            }

            let times = match self.get_voting_times(msg.source, &proof).await {
                Ok(times) => times,
                Err(e) => {
                    log::warn!("{e}");
                    return false;
                }
            };

            if times == 0 {
                log::warn!("Insufficient stake for peer {}", msg.source);
                return false;
            }

            if let Err(e) = Node::from_slice(&root_bytes) {
                log::warn!("Failed to deserialize root: {e}");
                return false;
            }

            self.voted.insert(msg.source);

            if self
                .votes
                .get(&root_bytes)
                .is_some_and(|(_, count)| *count >= self.total_times - times)
            {
                self.final_node = Some(root_bytes);
                return true;
            }

            let member_info = MemberInfo {
                public_key,
                proof,
                signature,
            };

            let entry = self
                .votes
                .entry(root_bytes)
                .or_insert_with(|| (Vec::new(), 0));

            entry.0.push(member_info);
            entry.1 += times;
        }

        false
    }
}
