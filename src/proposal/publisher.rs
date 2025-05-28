use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    constants::{HashArray, HASH_ARRAY_LENGTH, U16_LENGTH},
    crypto::keypair::{self, PublicKey, ResidentSignature, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, KeyArray, MerkleDag, Node},
    },
    proposal::{
        collector::{self, Collector, Context},
        pool::{hash_to_key_array, key_array_to_hash},
        vrf_elector::{self, VrfElector},
    },
    resident::Record,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;
type SplitedPairs = (Vec<(KeyArray, HashArray)>, Vec<(KeyArray, Record)>);

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

    #[error("{0}")]
    Elector(#[from] vrf_elector::Error),

    #[error("Peer {0} is already voted")]
    AlreadyVoted(PeerId),
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
struct Candidate {
    final_node: Vec<u8>,
    processed: HashSet<HashArray>,
    next: Vec<(KeyArray, Record)>,
    hash: HashArray,
}

#[derive(Debug)]
struct VoteContext {
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    candidate: Candidate,
    votes: Vec<MemberInfo>,
    voted: HashSet<PeerId>,
    goting_times: u32,
    total_times: u32,
    root: Node,
}

pub struct Publisher {
    transport: Arc<Transport>,
    elector: Arc<VrfElector>,
    secret_key: SecretKey,
    public_key: PublicKey,
    merkle_dag: MerkleDag,
    config: Config,
}

impl MemberInfo {
    pub fn new(
        public_key: PublicKey,
        proof: VrfProof,
        signature: ResidentSignature,
        hash: &HashArray,
    ) -> Result<Self> {
        if !public_key.verify_proof(proof.output(), &proof) {
            return Err(Error::InvalidPeerOrProof(public_key.to_peer_id()));
        }

        if !public_key.verify_signature(hash, &signature) {
            return Err(Error::InvalidPeerOrProof(public_key.to_peer_id()));
        }

        Ok(MemberInfo {
            public_key,
            proof,
            signature,
        })
    }

    pub fn new_unchecked(
        public_key: PublicKey,
        proof: VrfProof,
        signature: ResidentSignature,
    ) -> Self {
        MemberInfo {
            public_key,
            proof,
            signature,
        }
    }

    fn to_hash_map<I>(iter: I) -> HashMap<PublicKey, (VrfProof, ResidentSignature)>
    where
        I: IntoIterator<Item = Self>,
    {
        iter.into_iter()
            .map(|info| (info.public_key, (info.proof, info.signature)))
            .collect()
    }
}

impl Candidate {
    pub fn new(
        final_node: Vec<u8>,
        processed: HashSet<HashArray>,
        next: Vec<(KeyArray, Record)>,
    ) -> Self {
        let processed_bytes = Self::convert_processed_to_bytes(&processed);
        let next_bytes = Self::convert_next_to_bytes(&next);

        let mut hasher = blake3::Hasher::new();
        hasher.update(&final_node);
        hasher.update(&processed_bytes);
        hasher.update(&next_bytes);
        let hash = hasher.finalize().into();

        Self {
            final_node,
            processed,
            next,
            hash,
        }
    }

    fn convert_processed_to_bytes(processed: &HashSet<HashArray>) -> Vec<u8> {
        let mut processed_vec = processed.iter().copied().collect::<Vec<_>>();
        processed_vec.sort_unstable();

        let mut bytes = Vec::with_capacity(processed.len() * HASH_ARRAY_LENGTH);
        processed_vec.into_iter().for_each(|hash| {
            bytes.extend(hash);
        });

        bytes
    }

    fn convert_next_to_bytes(next: &[(KeyArray, Record)]) -> Vec<u8> {
        next.iter()
            .cloned()
            .flat_map(|(key, record)| {
                let mut bytes = Vec::with_capacity(U16_LENGTH + HASH_ARRAY_LENGTH);
                bytes.extend(key_array_to_hash(key));
                bytes.extend(record.hash());
                bytes
            })
            .collect()
    }

    pub fn hash(&self) -> &HashArray {
        &self.hash
    }
}

impl VoteContext {
    pub async fn add_vote(&mut self, peer_id: PeerId, member_info: MemberInfo) -> Result<()> {
        if member_info.public_key.to_peer_id() != peer_id {
            return Err(Error::InvalidPeerOrProof(peer_id));
        }

        if !self.voted.insert(peer_id) {
            return Err(Error::AlreadyVoted(peer_id));
        }

        let times = self
            .get_voting_times(peer_id, &member_info.public_key, &member_info.proof)
            .await?;

        if member_info
            .public_key
            .verify_proof(self.candidate.hash(), &member_info.proof)
        {
            self.goting_times += times;
            self.votes.push(member_info);
        }

        self.total_times += times;
        self.voted.insert(peer_id);
        self.total_times += times;

        Ok(())
    }

    pub async fn add_vote_unchecked(
        &mut self,
        peer_id: PeerId,
        member_info: MemberInfo,
    ) -> Result<()> {
        self.add_vote(peer_id, member_info).await
    }

    pub async fn get_voting_times(
        &self,
        peer_id: PeerId,
        public_key: &PublicKey,
        proof: &VrfProof,
    ) -> Result<u32> {
        let stakes = self
            .get_peer_stakes(&peer_id)
            .await?
            .ok_or(Error::InsufficientStake(peer_id))?;

        let times = self
            .elector
            .calc_times_with_proof(stakes, public_key, proof)?;

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

    pub fn get_result(self) -> Option<(Candidate, Vec<MemberInfo>)> {
        if self.is_elected() {
            Some((self.candidate, self.votes))
        } else {
            None
        }
    }

    fn is_elected(&self) -> bool {
        let threshold = self.total_times * 2 / 3;
        self.goting_times >= threshold
    }
}

impl Publisher {
    pub fn new(
        transport: Arc<Transport>,
        elector: Arc<VrfElector>,
        secret_key: SecretKey,
        public_key: PublicKey,
        config: Config,
    ) -> Self {
        let merkle_dag = MerkleDag::new(transport.clone(), config.batch_size);

        Self {
            transport,
            elector,
            secret_key,
            public_key,
            merkle_dag,
            config,
        }
    }

    pub fn set_elector(&mut self, elector: Arc<VrfElector>) {
        self.elector = elector;
    }

    pub async fn publish(
        &mut self,
        original: Node,
        pairs: Vec<(KeyArray, Record)>,
        proof: VrfProof,
        times: u32,
    ) -> Result<()> {
        let (current, next) = self.split_pairs(pairs);
        let current_set: HashSet<_> = current.iter().map(|(_, hash)| *hash).collect();

        self.merkle_dag.change_root(original);
        self.merkle_dag.batch_insert(current).await?;

        let root_bytes = self.merkle_dag.root().to_vec().await;
        let candidate = Candidate::new(root_bytes, current_set, next);
        let signature = self.publish_vote(*candidate.hash(), proof.clone()).await?;

        let mut ctx = VoteContext {
            transport: self.transport.clone(),
            elector: self.elector.clone(),
            candidate,
            votes: Vec::new(),
            voted: HashSet::new(),
            goting_times: 0,
            total_times: times,
            root: self.merkle_dag.root().clone(),
        };

        ctx.add_vote_unchecked(
            self.public_key.to_peer_id(),
            MemberInfo::new_unchecked(self.public_key.clone(), proof, signature),
        )
        .await?;

        if let Some((candidate, infos)) = self.collect_votes(ctx).await? {
            let payload = gossipsub::Payload::ProposalProcessingComplete {
                final_node: candidate.final_node,
                processed: candidate.processed,
                next: candidate.next,
                proofs: MemberInfo::to_hash_map(infos),
            };

            self.transport
                .publish(&self.config.external_topic, payload)
                .await?;
        }

        Ok(())
    }

    fn split_pairs(&self, mut pairs: Vec<(KeyArray, Record)>) -> SplitedPairs {
        let split_point = std::cmp::min(pairs.len(), self.config.per_time_max_records);
        let next = pairs.split_off(split_point);
        let current = pairs
            .into_iter()
            .map(|(key, record)| (key, record.hash()))
            .collect();

        (current, next)
    }

    async fn publish_vote(&self, hash: HashArray, proof: VrfProof) -> Result<ResidentSignature> {
        let signature = self.secret_key.sign(hash)?;

        let payload = gossipsub::Payload::ConsensusCandidate {
            proof,
            public_key: self.public_key.clone(),
            signature: signature.clone(),
        };

        self.transport
            .publish(&self.config.internal_topic, payload)
            .await?;

        Ok(signature)
    }

    async fn collect_votes(
        &self,
        ctx: VoteContext,
    ) -> Result<Option<(Candidate, Vec<MemberInfo>)>> {
        let rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut collector = Collector::<VoteContext>::new();
        collector.start(rx, ctx).await;

        let ctx = collector.wait_until(self.config.network_latency).await?;

        Ok(ctx.get_result())
    }
}

#[async_trait::async_trait]
impl Context for VoteContext {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool {
        if let gossipsub::Payload::ConsensusCandidate {
            proof,
            public_key,
            signature,
        } = msg.payload
        {
            let member_info =
                match MemberInfo::new(public_key, proof, signature, self.candidate.hash()) {
                    Ok(info) => info,
                    Err(e) => {
                        log::warn!("Invalid member info: {e}");
                        return false;
                    }
                };

            if let Err(e) = self.add_vote(msg.source, member_info).await {
                log::warn!("Failed to get voting times: {e}");
                return false;
            }
        }

        false
    }
}
