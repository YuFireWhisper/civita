use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::PeerId;
use tokio::time::Duration;

use crate::{
    consensus::{
        proposal_pool::{
            member_manager::MemberManager, proposal_collector::ProposalCollector,
            signature_collector::SignatureCollector, vote_manager::VoteManager,
        },
        signed_result::SignedResult,
        vrf_elector::{self, VrfElector},
    },
    constants::HashArray,
    crypto::keypair::{self, PublicKey, ResidentSignature, SecretKey, VrfProof},
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self, Node},
    },
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

mod member_manager;
mod proposal_collector;
mod signature_collector;
mod vote_manager;

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
    Keypair(#[from] keypair::Error),

    #[error("{0}")]
    Collector(#[from] proposal_collector::Error),

    #[error("Proposal pool not started")]
    NotStarted,

    #[error("{0}")]
    MemberManager(#[from] member_manager::Error),
}

pub struct Config {
    pub external_topic: String,
    pub internal_topic: String,
    pub num_members: u32,
    pub network_latency: Duration,
}

struct Context {
    proposal_collector: ProposalCollector,
    own_proof: VrfProof,
    own_weight: u32,
    own_proposals: Option<HashSet<HashArray>>,
    root: Option<Node>,
    total_stakes: u32,
    input: Vec<u8>,
}

pub struct ProposalPool {
    transport: Arc<Transport>,
    secret_key: SecretKey,
    public_key: PublicKey,
    elector: Arc<VrfElector>,
    ctx: Option<Context>,
    config: Config,
}

impl Context {
    pub fn own_proposals_or_unwrap(&self) -> HashSet<HashArray> {
        self.own_proposals
            .as_ref()
            .expect("Proposals should be present")
            .clone()
    }

    pub fn root_or_unwrap(&self) -> Node {
        self.root.clone().expect("Root should be present")
    }
}

impl ProposalPool {
    pub fn new(transport: Arc<Transport>, secret_key: SecretKey, config: Config) -> Self {
        let public_key = secret_key.to_public_key();
        let elector = VrfElector::new(secret_key.clone(), config.num_members);

        Self {
            transport,
            secret_key,
            public_key,
            elector: Arc::new(elector),
            ctx: None,
            config,
        }
    }

    pub async fn start(&mut self, input: Vec<u8>, stake: u32, total_stakes: u32) -> Result<()> {
        let (proof, times) = self.elector.generate(&input, stake, total_stakes)?;

        if times == 0 {
            return Ok(());
        }

        let mut collector = ProposalCollector::new(self.transport.clone());
        collector.start(&self.config.external_topic).await?;

        let ctx = Context {
            proposal_collector: collector,
            own_proof: proof,
            own_weight: times,
            own_proposals: None,
            root: None,
            total_stakes,
            input,
        };

        self.ctx = Some(ctx);

        Ok(())
    }

    pub async fn settle(&mut self, root: Node) -> Result<SignedResult<HashSet<HashArray>>> {
        let mut ctx = self.ctx.take().ok_or(Error::NotStarted)?;

        ctx.own_proposals = Some(ctx.proposal_collector.settle().await?);
        ctx.root = Some(root);
        self.publish_proposals(&ctx).await?;
        let (final_proposals, members) = self.collect_and_vote(&ctx).await?;

        self.consensus_result(final_proposals, members).await
    }

    async fn publish_proposals(&self, ctx: &Context) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusProposal {
            proposal_set: ctx.own_proposals_or_unwrap(),
            proof: ctx.own_proof.clone(),
            public_key: self.public_key.clone(),
        };

        self.transport
            .publish(&self.config.external_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_and_vote(
        &self,
        ctx: &Context,
    ) -> Result<(HashSet<HashArray>, HashMap<PeerId, (PublicKey, VrfProof)>)> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut member_manager = MemberManager::new(
            self.transport.clone(),
            self.elector.clone(),
            ctx.input.clone(),
            ctx.total_stakes,
            ctx.root_or_unwrap(),
        );
        member_manager
            .add_member(
                self.transport.self_peer(),
                self.public_key.clone(),
                ctx.own_proof.clone(),
            )
            .await?;

        let mut vote_manager = VoteManager::new();
        vote_manager.add_votes(ctx.own_proposals_or_unwrap().iter(), ctx.own_weight);
        vote_manager.add_total_votes(ctx.own_weight);

        while let Some(msg) = rx.recv().await {
            if let gossipsub::Payload::ConsensusProposal {
                proposal_set,
                proof,
                public_key,
            } = msg.payload
            {
                if let Ok(Some(times)) = member_manager
                    .add_member(msg.source, public_key, proof)
                    .await
                {
                    vote_manager.add_votes(proposal_set.iter(), times);
                    vote_manager.add_total_votes(times);
                }
            }
        }

        Ok((
            vote_manager.get_winners(),
            member_manager.get_member_proofs(),
        ))
    }

    pub async fn consensus_result(
        &self,
        final_proposals: HashSet<HashArray>,
        members: HashMap<PeerId, (PublicKey, VrfProof)>,
    ) -> Result<SignedResult<HashSet<HashArray>>> {
        let final_hash = self.calc_final_hash(&final_proposals);

        let signature = self.secret_key.sign(final_hash)?;

        self.publish_signature(signature).await?;

        let signatures = self.collect_signatures(final_hash, members).await?;

        Ok(SignedResult {
            result: final_proposals,
            members: signatures,
        })
    }

    fn calc_final_hash(&self, final_proposals: &HashSet<HashArray>) -> HashArray {
        let mut hasher = blake3::Hasher::new();
        let mut sorted_proposals: Vec<_> = final_proposals.iter().collect();
        sorted_proposals.sort();

        for proposal in sorted_proposals {
            hasher.update(proposal);
        }

        hasher.finalize().into()
    }

    async fn publish_signature(&self, signature: ResidentSignature) -> Result<()> {
        let payload = gossipsub::Payload::ConsensusProposalResult { signature };

        self.transport
            .publish(&self.config.internal_topic, payload)
            .await?;

        Ok(())
    }

    async fn collect_signatures(
        &self,
        final_hash: HashArray,
        mut members: HashMap<PeerId, (PublicKey, VrfProof)>,
    ) -> Result<HashMap<PublicKey, (VrfProof, ResidentSignature)>> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.internal_topic)
            .await?;

        let mut collector = SignatureCollector::new(final_hash);

        while let Some(msg) = rx.recv().await {
            let (public_key, proof) = match members.remove(&msg.source) {
                Some((public_key, proof)) => (public_key, proof),
                None => continue,
            };

            if let gossipsub::Payload::ConsensusProposalResult { signature } = msg.payload {
                collector.add_signature(public_key, proof, signature);
            }
        }

        Ok(collector.get_signatures())
    }
}
