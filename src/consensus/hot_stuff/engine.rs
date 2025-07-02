use std::{collections::BTreeSet, marker::PhantomData, sync::Arc};

use dashmap::mapref::one::Ref;

use crate::{
    consensus::{
        hot_stuff::{
            chain,
            proposal_pool::{self, ProposalPool},
            utils::{self, QuorumCertificate, ViewNumber},
        },
        randomizer::{self, Randomizer},
    },
    crypto::{
        self,
        traits::{
            hasher::{Hasher, Multihash},
            suite::Suite,
            SecretKey, Signer, VerifiySignature,
        },
    },
    network::{
        storage::Storage,
        transport::{self, protocols::gossipsub, Kad},
    },
    proposal::Proposal,
    resident,
    traits::serializable::{self, ConstantSize, Serializable},
    utils::mpt::Mpt,
};

#[cfg(not(test))]
use crate::network::transport::Transport;

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

type PublicKey<S> = <S as Suite>::PublicKey;
type Signature<S> = <S as Suite>::Signature;
type DrawProof<S> = randomizer::DrawProof<<S as Suite>::Proof>;
type ProofPair<S> = (DrawProof<S>, Signature<S>);

type Block<S, P> = utils::Block<P, PublicKey<S>, ProofPair<S>>;
type View<S, P> = utils::View<Block<S, P>, PublicKey<S>, ProofPair<S>>;
type Chain<S, P, ST = Arc<Kad>> = chain::Chain<Block<S, P>, PublicKey<S>, ProofPair<S>, ST>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Kad(#[from] transport::protocols::kad::Error),

    #[error("{0}")]
    Randomizer(#[from] randomizer::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    ProposalPool(#[from] proposal_pool::Error),

    #[error("{0}")]
    Proposal(String),

    #[error("{0}")]
    Crypto(#[from] crypto::Error),
}

pub struct Config {
    pub proposal_topic: String,
    pub view_topic: String,
    pub vote_topic: String,

    pub proposal_pool_capacity: usize,
    pub expected_leaders: u16,
    pub expected_members: u16,
    pub wait_leader_timeout: tokio::time::Duration,
}

pub struct Engine<P, S, H>
where
    P: Proposal,
    S: Suite,
    H: Hasher,
{
    transport: Arc<Transport>,
    sk: S::SecretKey,
    proposal_pool: ProposalPool<P>,
    chain: Chain<S, P>,
    records: Mpt<resident::Record>,
    randomizer: Randomizer,
    config: Config,
    _marker: PhantomData<H>,
}

impl<P, S, H> Engine<P, S, H>
where
    P: Proposal,
    S: Suite,
    H: Hasher,
{
    pub async fn spawn(
        transport: Arc<Transport>,
        sk: S::SecretKey,
        chain: Chain<S, P>,
        root_hash: Multihash,
        config: Config,
    ) -> Result<()> {
        let rx = transport.listen_on_topic(&config.proposal_topic).await?;
        let proposal_pool = ProposalPool::<P>::new(rx, config.proposal_pool_capacity);
        let records = Mpt::with_root(transport.kad(), root_hash);
        let randomizer = Randomizer::new(config.expected_leaders, config.expected_members);

        tokio::spawn(async move {
            let mut engine = Self {
                transport,
                sk,
                proposal_pool,
                chain,
                records,
                randomizer,
                config,
                _marker: PhantomData,
            };

            if let Err(e) = engine.run().await {
                log::error!("Engine error: {e}");
            }

            log::info!("Engine stopped");
        });

        Ok(())
    }

    async fn run(&mut self) -> Result<()> {
        let mut view_rx = self
            .transport
            .listen_on_topic(&self.config.view_topic)
            .await?;

        let mut vote_rx = self
            .transport
            .listen_on_topic(&self.config.vote_topic)
            .await?;

        let mut leader_proof = None;
        let mut validator_proof = None;

        loop {
            tokio::select! {
                Some(msg) = view_rx.recv() => {
                    let gossipsub::Payload::View(hash) = msg.payload else {
                        continue;
                    };

                    self.handle_view(hash, &mut leader_proof, &mut validator_proof).await?;
                }

                Some(msg) = vote_rx.recv() => {
                    let gossipsub::Payload::Vote { hash, pk, proof, sig } = msg.payload else {
                        continue;
                    };

                    let pk = PublicKey::<S>::from_slice(&pk)?;
                    let proof = DrawProof::<S>::from_slice(&proof)?;
                    let sig = Signature::<S>::from_slice(&sig)?;

                    self.chain
                        .on_receive_vote(hash, pk, (proof, sig))
                        .await?;
                }
            }
        }
    }

    async fn handle_view(
        &mut self,
        view_hash: Multihash,
        leader_proof: &mut Option<DrawProof<S>>,
        validator_proof: &mut Option<DrawProof<S>>,
    ) -> Result<()> {
        if !self.chain.is_safe_view(&view_hash).await? {
            return Ok(());
        }

        let Some(cur_view) = self.chain.get_view(&view_hash).await? else {
            return Ok(());
        };

        if !self.is_leader_valid(cur_view.value()).await? {
            return Ok(());
        }

        let Some(justify) = cur_view.justify.as_ref() else {
            return Ok(());
        };

        if !self.is_justify_valid(justify).await? {
            return Ok(());
        }

        let cur_view_clone = cur_view.value().clone();

        drop(cur_view);

        let _ = self.chain.update(&view_hash).await?;

        if let Some(proof) = validator_proof.take() {
            let cur_cmd = cur_view_clone.cmd.as_ref().expect("Command should exist");

            if let Some((exec_hash, total_stakes)) = self.apply_proposal(&cur_cmd.proposals).await?
            {
                if exec_hash != cur_cmd.executed_root_hash
                    || total_stakes != cur_cmd.executed_total_stakes
                {
                    return Ok(());
                }

                let pk = self.sk.public_key();
                let pk_bytes = pk.to_vec()?;
                let proof_bytes = proof.to_vec()?;
                let sig = self.sk.sign(&cur_view_clone.hash.to_bytes())?;
                let sig_bytes = sig.to_vec()?;

                let vote = gossipsub::Payload::Vote {
                    hash: cur_view_clone.hash,
                    pk: pk_bytes,
                    proof: proof_bytes,
                    sig: sig_bytes,
                };

                self.transport
                    .publish(&self.config.vote_topic, vote)
                    .await?;

                self.chain
                    .on_receive_vote(cur_view_clone.hash, pk, (proof, sig))
                    .await?;
            }
        }

        if let Some(proof) = leader_proof.take() {
            let proposals = self.proposal_pool.get().await?;
            let (proposals, exec_hash, total_stakes) =
                self.apply_proposal_or_reduce(proposals).await?;

            let pk = self.sk.public_key().clone();
            let sig = self.sk.sign(&view_hash.to_bytes())?;

            let block = Block::<S, P> {
                leader: (pk, (proof, sig)),
                proposals,
                executed_root_hash: exec_hash,
                executed_total_stakes: total_stakes,
            };

            let view = self.chain.on_propose::<H>(block).await?;
            let view_bytes = view.to_vec()?;

            self.transport.kad().put(view.hash, view_bytes).await?;

            let payload = gossipsub::Payload::View(view.hash);

            self.transport
                .publish(&self.config.view_topic, payload)
                .await?;
        }

        let Some(exec_view) = self.chain.executed_view().await? else {
            return Ok(());
        };

        let Some(exec_cmd) = exec_view.cmd.as_ref() else {
            return Ok(());
        };

        let pk_hash = H::hash(&self.sk.public_key().to_vec()?);

        let stakes = self
            .records
            .get(&pk_hash.to_bytes())
            .await?
            .map(|r| r.stakes)
            .unwrap_or(0);

        let seed = Self::generate_seed(&exec_view.hash, self.chain.leaf_view_number().await + 1);

        *leader_proof = self.randomizer.draw::<H, _>(
            seed.digest(),
            exec_cmd.executed_total_stakes,
            &self.sk,
            stakes,
            true,
        )?;

        *validator_proof = self.randomizer.draw::<H, _>(
            seed.digest(),
            exec_cmd.executed_total_stakes,
            &self.sk,
            stakes,
            false,
        )?;

        Ok(())
    }

    async fn is_leader_valid(&self, cur_view: &View<S, P>) -> Result<bool> {
        let Some((pk, (proof, sig))) = cur_view.cmd.as_ref().map(|cmd| &cmd.leader) else {
            return Ok(false);
        };

        let Some(exec_view) = self.get_exec_view_at(&cur_view.hash).await? else {
            return Ok(false);
        };

        let Some(exec_cmd) = exec_view.cmd.as_ref() else {
            return Ok(false);
        };

        let seed = Self::generate_seed(&exec_view.hash, cur_view.number);

        self.is_role_valid(
            &cur_view.hash.to_bytes(),
            seed.digest(),
            exec_cmd.executed_total_stakes,
            (pk, (proof, sig)),
            true,
        )
        .await
        .map(|res| res.is_some())
    }

    async fn get_exec_view_at(
        &self,
        view_hash: &Multihash,
    ) -> Result<Option<Ref<Multihash, View<S, P>>>> {
        let Some(exec_hash) = self.chain.exec_hash_at(view_hash).await? else {
            return Ok(None);
        };

        let Some(view) = self.chain.get_view(&exec_hash).await? else {
            return Ok(None);
        };

        if view.cmd.is_none() {
            return Ok(None);
        }

        Ok(Some(view))
    }

    fn generate_seed(exec_hash: &Multihash, view: ViewNumber) -> Multihash {
        let mut bytes = Vec::with_capacity(exec_hash.serialized_size() + ViewNumber::SIZE);

        exec_hash.to_writer(&mut bytes).unwrap();
        view.to_writer(&mut bytes).unwrap();

        H::hash(&bytes)
    }

    async fn is_role_valid(
        &self,
        view_hash: &[u8],
        seed: &[u8],
        total_stakes: u32,
        info: (&PublicKey<S>, (&DrawProof<S>, &Signature<S>)),
        is_leader: bool,
    ) -> Result<Option<u32>> {
        let (pk, (proof, sig)) = info;

        if pk.verify_signature(view_hash, sig).is_err() {
            return Ok(None);
        }

        let pk_hash = H::hash(&pk.to_vec().expect("PublicKey serialization failed"));

        let Some(stakes) = self
            .records
            .get(&pk_hash.to_bytes())
            .await?
            .map(|r| r.stakes)
        else {
            return Ok(None);
        };

        if stakes == 0 {
            return Ok(None);
        }

        if !self.randomizer.verify::<H, S::PublicKey>(
            seed,
            total_stakes,
            pk,
            stakes,
            proof,
            is_leader,
        ) {
            return Ok(None);
        }

        Ok(Some(stakes))
    }

    async fn is_justify_valid(
        &self,
        justify: &QuorumCertificate<Multihash, PublicKey<S>, ProofPair<S>>,
    ) -> Result<bool> {
        let Some(jus_view) = self.chain.get_view(&justify.view).await? else {
            return Ok(false);
        };

        let Some(exec_view) = self.get_exec_view_at(&justify.view).await? else {
            return Ok(false);
        };

        let Some(exec_cmd) = exec_view.cmd.as_ref() else {
            return Ok(false);
        };

        let seed = Self::generate_seed(&exec_view.hash, jus_view.number);

        let jus_view_bytes = jus_view.hash.to_bytes();

        let mut total_votes = 0u32;

        for (pk, (proof, sig)) in justify.sigs.iter() {
            let Some(stakes) = self
                .is_role_valid(
                    &jus_view_bytes,
                    seed.digest(),
                    exec_cmd.executed_total_stakes,
                    (pk, (proof, sig)),
                    false,
                )
                .await?
            else {
                return Ok(false);
            };

            total_votes += stakes;
        }

        if total_votes < self.config.expected_members as u32 {
            return Ok(false);
        }

        Ok(true)
    }

    async fn apply_proposal(&mut self, proposal: &BTreeSet<P>) -> Result<Option<(Multihash, u32)>> {
        self.records.rollback();

        let mut total_stakes = 0u32;

        for prop in proposal {
            if !prop
                .verify::<H>(&self.records)
                .await
                .map_err(|e| Error::Proposal(e.to_string()))?
            {
                return Ok(None);
            }

            prop.apply::<H>(&mut self.records)
                .await
                .map_err(|e| Error::Proposal(e.to_string()))?;

            let stakes = prop
                .impact_stakes()
                .map_err(|e| Error::Proposal(e.to_string()))?;

            total_stakes = total_stakes.wrapping_add_signed(stakes);
        }

        let Some(hash) = self.records.root_hash() else {
            return Ok(None);
        };

        self.records.rollback();

        Ok(Some((hash, total_stakes)))
    }

    async fn apply_proposal_or_reduce(
        &mut self,
        proposal: BTreeSet<P>,
    ) -> Result<(BTreeSet<P>, Multihash, u32)> {
        self.records.rollback();

        let mut total_stakes = 0u32;

        let mut finals = BTreeSet::new();

        for prop in proposal.into_iter() {
            if !prop
                .verify::<H>(&self.records)
                .await
                .map_err(|e| Error::Proposal(e.to_string()))?
            {
                continue;
            }

            if (prop.apply::<H>(&mut self.records).await).is_err() {
                continue;
            }

            let stakes = prop
                .impact_stakes()
                .map_err(|e| Error::Proposal(e.to_string()))?;

            total_stakes = total_stakes.wrapping_add_signed(stakes);

            finals.insert(prop);
        }

        let Some(hash) = self.records.root_hash() else {
            panic!("Root hash should exist after applying proposals");
        };

        self.records.rollback();

        Ok((finals, hash, total_stakes))
    }
}
