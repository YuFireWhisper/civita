use std::{mem, sync::Arc};

use libp2p::{Multiaddr, PeerId};

use crate::{
    consensus::{
        hot_stuff::{
            self, chain,
            elector::{self, Elector},
            proposal_pool::ProposalPool,
            utils,
        },
        randomizer::{self},
    },
    crypto::traits::{
        hasher::{HashArray, Hasher},
        suite::{self, Suite},
    },
    network::transport::{
        self,
        protocols::gossipsub,
        store::merkle_dag::{self},
    },
    proposal::Proposal,
    traits::serializable::{self, Serializable},
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

type Block<S, P> = utils::Block<HashArray<<S as suite::HasherConfig>::Hasher>, P>;
type View<S, P> = utils::View<
    Block<S, P>,
    <S as Suite>::PublicKey,
    (<S as Suite>::Proof, <S as Suite>::Signature),
>;
type Chain<S, P> = hot_stuff::chain::Chain<
    Block<S, P>,
    <S as Suite>::PublicKey,
    (<S as Suite>::Proof, <S as Suite>::Signature),
>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    MerkleDag(#[from] merkle_dag::Error),

    #[error("{0}")]
    Randomizer(#[from] randomizer::Error),

    #[error("{0}")]
    Chain(#[from] chain::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    Elector(#[from] elector::Error),
}

pub struct Config {
    pub proposal_topic: String,
    pub election_topic: String,
    pub view_topic: String,

    pub proposal_pool_capacity: usize,
    pub expected_leaders: u16,
    pub expected_members: u16,
    pub wait_leader_timeout: tokio::time::Duration,
}

pub struct Engine<P: Proposal, S: Suite> {
    transport: Arc<Transport>,
    sk: S::SecretKey,
    proposal_pool: ProposalPool<P>,
    elector: Elector<S>,
    chain: Chain<S, P>,
    leader: (PeerId, Multiaddr),
    config: Config,
}

impl<P, S> Engine<P, S>
where
    P: Proposal + Clone + Serializable,
    S: Suite,
    S::Hasher: merkle_dag::HasherConfig,
{
    pub async fn spawn(
        transport: Arc<Transport>,
        sk: S::SecretKey,
        chain: Chain<S, P>,
        leader: (PeerId, Multiaddr),
        config: Config,
    ) -> Result<()> {
        let rx = transport.listen_on_topic(&config.proposal_topic).await?;

        tokio::spawn(async move {
            let proposal_pool = ProposalPool::<P>::new(rx, config.proposal_pool_capacity);

            let elector_config = elector::Config {
                expected_leaders: config.expected_leaders,
                expected_members: config.expected_members,
                topic: config.election_topic.clone(),
                wait_leader_timeout: config.wait_leader_timeout,
            };

            let elector = Elector::<S>::new(transport.clone(), sk.clone(), elector_config);

            let mut engine = Self {
                transport,
                sk,
                proposal_pool,
                elector,
                chain,
                leader,
                config,
            };

            if let Err(e) = engine.run().await {
                log::error!("Engine error: {e}");
            }

            log::info!("Engine stopped");
        });

        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        loop {
            self.new_round().await?;
        }
    }

    async fn new_round(&mut self) -> Result<()> {
        let exec_view = self.chain.executed_view()?;
        let leaf_view = self.chain.leaf_view()?;

        let exec_cmd = exec_view
            .cmd()
            .expect("Executed view should always be normal view");

        let seed = Self::generate_seed(exec_cmd, leaf_view.number() + 1)?;
        let total_stakes = exec_cmd.total_stakes;
        let root_hash = &exec_cmd.root_hash;

        let Some(leader) = self
            .elector
            .elect(seed, total_stakes, root_hash.clone())
            .await?
        else {
            log::warn!("No leader elected for round {}", leaf_view.number() + 1);
            return Ok(());
        };

        // Todo: If we are the leader, we should start the proposal process

        let leader = mem::replace(&mut self.leader, leader);
        let res_view = match self.wait_for_leader(leader.0).await? {
            Some(node) => node,
            None => return Ok(()),
        };

        // Todo: We should fetch missing nodes from the network
        // Now we just check the res is direct execution of the leaf node
        if res_view.number() != leaf_view.number() {
            log::warn!(
                "Leader view number mismatch: expected {}, got {}",
                leaf_view.number(),
                res_view.number()
            );
            return Ok(());
        }

        // Todo: We should check the block is valid
        if !self.chain.is_valid_view(&res_view)? {
            log::warn!("Invalid view received from leader: {leader:?}");
            return Ok(());
        }

        // Todo: We need to send vote to the next leader
        self.chain.update(res_view)?;

        Ok(())
    }

    fn generate_seed(executed_cmd: &Block<S, P>, next_number: u64) -> Result<HashArray<S::Hasher>> {
        let mut bytes = Vec::new();
        executed_cmd.to_writer(&mut bytes)?;
        next_number.to_writer(&mut bytes)?;
        Ok(S::Hasher::hash(&bytes))
    }

    async fn wait_for_leader(&self, leader: PeerId) -> Result<Option<View<S, P>>> {
        let mut rx = self
            .transport
            .listen_on_topic(&self.config.view_topic)
            .await?;

        let res = tokio::time::timeout(self.config.wait_leader_timeout, async move {
            while let Some(msg) = rx.recv().await {
                if msg.source != leader {
                    continue;
                }

                let gossipsub::Payload::View { node } = msg.payload else {
                    continue;
                };

                return View::<S, P>::from_slice(&node).ok();
            }
            None
        })
        .await
        .unwrap_or_else(|_| None);

        Ok(res)
    }
}
