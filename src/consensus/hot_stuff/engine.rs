use std::sync::Arc;

use tokio::sync::mpsc;

use crate::{
    consensus::{
        hot_stuff::{
            chain::Chain,
            proposal_pool::{self, ProposalPool},
            utils::{Block, ProofPair, View, ViewNumber},
        },
        randomizer::Randomizer,
    },
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    network::{
        gossipsub::{self, Gossipsub},
        storage,
        transport::Transport,
    },
    proposal::MultiProposal,
    resident,
    traits::serializable::{self, ConstantSize, Serializable},
    utils::mpt::{self, MerklePatriciaTrie},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Gossipsub(#[from] gossipsub::Error),

    #[error("{0}")]
    Storage(#[from] storage::Error),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("{0}")]
    ProposalPool(#[from] proposal_pool::Error),
}

pub struct Config {
    pub prop_topic: u8,
    pub view_topic: u8,
    pub vote_topic: u8,

    pub proposal_pool_capacity: usize,
    pub expected_leaders: u16,
    pub expected_members: u16,
    pub wait_leader_timeout: tokio::time::Duration,
}

struct Vote {
    hash: Multihash,
    pk: PublicKey,
    proof: ProofPair,
    sig: Signature,
}

pub struct Engine<H> {
    gossipsub: Arc<Gossipsub>,
    sk: SecretKey,
    prop_pool: ProposalPool<H>,
    chain: Chain,
    records: MerklePatriciaTrie<H>,
    record: Option<resident::Record>,
    randomizer: Randomizer,
    config: Config,
}

impl<H: Hasher> Engine<H> {
    pub async fn spawn(
        transport: Arc<Transport>,
        chain: Chain,
        root: mpt::Node,
        record: Option<resident::Record>,
        config: Config,
    ) -> Result<(
        mpsc::Sender<(Multihash, bool)>,
        mpsc::Receiver<MultiProposal>,
    )> {
        let gossipsub = transport.gossipsub();
        let sk = transport.secret_key().clone();
        let rx = gossipsub.subscribe(config.prop_topic).await?;
        let (prop_pool, rx) =
            ProposalPool::<H>::new(rx, root.hash::<H>(), config.proposal_pool_capacity);
        let randomizer = Randomizer::new(config.expected_leaders, config.expected_members);
        let records = MerklePatriciaTrie::<H>::new_with_root(root);

        tokio::spawn(async move {
            let cur_view = chain.leaf_view_number().await + 1;

            let mut engine = Self {
                gossipsub,
                sk,
                prop_pool,
                chain,
                records,
                record,
                randomizer,
                config,
            };

            if let Err(e) = engine.run(cur_view).await {
                log::error!("Engine error: {e}");
            }

            log::info!("Engine stopped");
        });

        Ok(rx)
    }

    async fn run(&mut self, mut cur_view: ViewNumber) -> Result<()> {
        let mut view_rx = self.gossipsub.subscribe(self.config.view_topic).await?;
        let mut vote_rx = self.gossipsub.subscribe(self.config.vote_topic).await?;

        loop {
            let (exec_hash, total_stakes) = {
                let exec_block = &self.chain.executed_view().await.block;
                (
                    exec_block.executed_root_hash,
                    exec_block.executed_total_stakes,
                )
            };
            let seed = Self::generate_seed(&exec_hash, cur_view);

            if let Some(proof) = self.elect(seed.digest(), total_stakes, true) {
                if let Err(e) = self.as_leader(total_stakes, proof).await {
                    log::error!("Leader error: {e}");
                }
            }

            let Some(view) = self.wait_for_leader(&mut view_rx).await else {
                log::debug!("No leader found, waiting for next round");
                cur_view += 1;
                continue;
            };

            self.prop_pool
                .remove(view.block.props.keys().cloned().collect())
                .await?;
            self.chain.add_view(view.clone());
            self.chain.update(&view.hash).await;

            let view_hash = view.hash;

            if let Some(proof) = self.elect(seed.digest(), total_stakes, false) {
                if let Err(e) = self.as_validator(view, proof).await {
                    log::error!("Validator error: {e}");
                }
            }

            self.collect_votes(&mut vote_rx, &view_hash).await;
            cur_view += 1;
        }
    }

    fn generate_seed(exec_hash: &Multihash, view: ViewNumber) -> Multihash {
        let mut bytes = Vec::with_capacity(exec_hash.serialized_size() + ViewNumber::SIZE);

        exec_hash.to_writer(&mut bytes).unwrap();
        view.to_writer(&mut bytes).unwrap();

        H::hash(&bytes)
    }

    fn elect(&self, seed: &[u8], total_stakes: u32, is_leader: bool) -> Option<ProofPair> {
        let record = self.record.as_ref()?;
        let draw_proof =
            self.randomizer
                .draw::<H>(seed, total_stakes, &self.sk, record.stakes, is_leader)?;

        let key = self.sk.public_key().to_hash::<H>().to_bytes();
        let record_proof = self
            .records
            .generate_proof(
                &key,
                Some(record.to_vec().expect("Record serialization failed")),
            )
            .expect("Failed to generate existence proof");

        Some((draw_proof, record_proof))
    }

    async fn wait_for_leader(&mut self, view_rx: &mut mpsc::Receiver<Vec<u8>>) -> Option<View> {
        let timeout = tokio::time::sleep(self.config.wait_leader_timeout);
        tokio::pin!(timeout);

        let expected_view_number = self.chain.leaf_view_number().await + 1;

        let mut candidate: Option<View> = None;

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    log::debug!("Leader wait timeout");
                    return candidate;
                }

                Some(msg) = view_rx.recv() => {
                    let Ok(view) = View::from_slice(&msg) else {
                        continue;
                    };

                    if !self.chain.is_safe_view(&view.hash).await {
                        continue;
                    }

                    if !self.is_view_valid(expected_view_number, &view).await {
                        continue;
                    }

                    if let Some(cur_view) = candidate.as_mut() {
                        if view.block.leader.1.0.proof.to_hash() < cur_view.block.leader.1.0.proof.to_hash() {
                            *cur_view = view;
                        }
                    } else {
                        candidate = Some(view);
                    }
                }
            }
        }
    }

    async fn as_leader(&mut self, mut total_stakes: u32, proof: ProofPair) -> Result<()> {
        let props = self.prop_pool.get().await?;

        for prop in props.values() {
            for (proof, record) in prop.diff.values() {
                let value = H::hash(&record.to_vec().expect("Record serialization failed"));
                self.records.insert_uncheck(proof.clone(), value);
            }
            total_stakes = total_stakes.wrapping_add_signed(prop.total_stakes_diff);
        }

        let (execed_root_hash, diff) = self.records.uncommit_root();
        self.records.clear();

        let block = Block {
            leader: (self.sk.public_key(), proof),
            props,
            executed_root_hash: execed_root_hash,
            executed_mpt_diff: diff,
            executed_total_stakes: total_stakes,
        };

        let view = self.chain.on_propose::<H>(block).await?;
        let view_bytes = view.to_vec().expect("Failed to serialize view");

        self.gossipsub
            .publish(self.config.view_topic, view_bytes)
            .await?;

        Ok(())
    }

    async fn as_validator(&mut self, view: View, proof: ProofPair) -> Result<()> {
        let mut total_votes = 0u32;

        for prop in view.block.props.into_values() {
            for (_, (proof, record)) in prop.diff {
                let value = H::hash(&record.to_vec().expect("Record serialization failed"));
                if !self.records.insert(proof, value) {
                    return Ok(());
                }
            }
            total_votes = total_votes.wrapping_add_signed(prop.total_stakes_diff);
        }

        let (execed_root_hash, diff) = self.records.uncommit_root();

        if execed_root_hash != view.block.executed_root_hash
            || total_votes != view.block.executed_total_stakes
            || diff != view.block.executed_mpt_diff
        {
            return Ok(());
        }

        let sig = self.sk.sign(&view.hash.to_bytes());

        let vote = Vote {
            hash: view.hash,
            pk: self.sk.public_key(),
            proof,
            sig,
        };

        self.gossipsub
            .publish(self.config.vote_topic, vote.to_vec()?)
            .await?;

        Ok(())
    }

    async fn is_view_valid(&self, expected_view_number: ViewNumber, view: &View) -> bool {
        if view.number != expected_view_number {
            return false;
        }

        let cur_exec_view = self.chain.executed_view().await;
        let cur_root_hash = cur_exec_view.block.executed_root_hash;
        let cur_total_stakes = cur_exec_view.block.executed_total_stakes;

        if self
            .is_role_valid(
                &cur_root_hash,
                cur_total_stakes,
                &view.block.leader.0,
                &view.block.leader.1,
                true,
            )
            .is_none()
        {
            return false;
        }

        let pre_view = self.chain.executed_view_parent_view().await;
        let pre_root_hash = pre_view.block.executed_root_hash;
        let pre_total_stakes = pre_view.block.executed_total_stakes;

        let mut total_votes = 0u32;
        for (pk, (proof_pair, sig)) in &view.justify.proofs {
            if pk.verify_signature(&view.hash.to_bytes(), sig) {
                continue;
            }

            let Some(stakes) =
                self.is_role_valid(&pre_root_hash, pre_total_stakes, pk, proof_pair, false)
            else {
                return false;
            };

            total_votes += stakes;
        }

        if total_votes < self.config.expected_members as u32 {
            return false;
        }

        true
    }

    fn is_role_valid(
        &self,
        root_hash: &Multihash,
        total_stakes: u32,
        pk: &PublicKey,
        proof_pair: &ProofPair,
        is_leader: bool,
    ) -> Option<u32> {
        let (draw_proof, record_proof) = proof_pair;

        let key = pk.to_hash::<H>().to_bytes();
        if !record_proof.verify_with_key::<H>(root_hash, &key) {
            return None;
        }

        let value = record_proof.value()?;
        let record = resident::Record::from_slice(value).expect("Failed to deserialize record");

        if record.stakes == 0 {
            return None;
        }

        let root_hash_bytes = root_hash.to_bytes();
        if !self.randomizer.verify::<H>(
            &root_hash_bytes,
            total_stakes,
            pk,
            record.stakes,
            draw_proof,
            is_leader,
        ) {
            return None;
        }

        Some(record.stakes)
    }

    async fn collect_votes(
        &mut self,
        vote_rx: &mut mpsc::Receiver<Vec<u8>>,
        view_hash: &Multihash,
    ) {
        let timeout = tokio::time::sleep(self.config.wait_leader_timeout);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                _ = &mut timeout => {
                    break;
                }

                Some(msg) = vote_rx.recv() => {
                    let Ok(vote) = Vote::from_slice(&msg) else {
                        continue;
                    };

                    if vote.hash != *view_hash {
                        continue;
                    }

                    self.chain
                        .on_receive_vote(vote.hash, vote.pk, vote.proof, vote.sig).await;
                }
            }
        }
    }
}

impl Serializable for Vote {
    fn serialized_size(&self) -> usize {
        self.hash.serialized_size()
            + self.pk.serialized_size()
            + self.proof.serialized_size()
            + self.sig.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            hash: Multihash::from_reader(reader)?,
            pk: PublicKey::from_reader(reader)?,
            proof: ProofPair::from_reader(reader)?,
            sig: Signature::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.hash.to_writer(writer)?;
        self.pk.to_writer(writer)?;
        self.proof.to_writer(writer)?;
        self.sig.to_writer(writer)?;

        Ok(())
    }
}
