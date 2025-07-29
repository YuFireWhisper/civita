use std::{collections::HashMap, sync::Arc};

use civita_serialize_derive::Serialize;
use dashmap::{DashMap, DashSet};
use libp2p::PeerId;
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            self,
            tree::{
                dag::{Dag, Node, ValidationResult},
                node::{BlockNode, UnifiedNode},
            },
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::trie::{Trie, Weight},
};

pub mod dag;
mod node;

#[derive(Debug)]
#[derive(Default)]
pub struct ProcessResult {
    pub validated: Vec<PeerId>,
    pub invalidated: Vec<PeerId>,
    pub phantoms: Vec<Multihash>,
}

#[derive(Serialize)]
pub struct SyncState {
    tip_block: Block,
    tip_cumulative_weight: Weight,
    checkpoint_block: Block,
    checkpoint_total_weight: Weight,
    tip_guide: HashMap<Multihash, Vec<u8>>,
}

pub enum Mode {
    Archive,
    Normal(Vec<Vec<u8>>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
struct State {
    tip_cumulative_weight: Weight,
    tip_hash: Multihash,

    current_checkpoint_total_weight: Weight,
    checkpoints: Vec<Multihash>,
}

pub struct Tree<H: Hasher> {
    sk: SecretKey,

    block_dag: ParkingRwLock<Dag<BlockNode<H>>>,
    proposal_dags: DashMap<Multihash, Dag<UnifiedNode<H>>>,

    pending_blocks: DashMap<Multihash, Multihash>,
    invalidated_hashes: DashSet<Multihash>,

    proposal_to_block: DashMap<Multihash, Multihash>,

    state: Arc<ParkingRwLock<State>>,
    sources: DashMap<Multihash, PeerId>,
    mode: Arc<Mode>,
}

impl ProcessResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_validated(&mut self, source: PeerId) {
        self.validated.push(source);
    }

    pub fn add_invalidated(&mut self, source: PeerId) {
        self.invalidated.push(source);
    }

    pub fn add_phantom(&mut self, id: Multihash) {
        self.phantoms.push(id);
    }

    pub fn from_validation_result<N: Node>(
        result: &ValidationResult<N>,
        metadatas: &DashMap<N::Id, PeerId>,
    ) -> Self {
        let mut process_result = Self::new();
        process_result.merge_from_validation_result(result, metadatas);
        process_result
    }

    pub fn merge_from_validation_result<N: Node>(
        &mut self,
        result: &ValidationResult<N>,
        metadatas: &DashMap<N::Id, PeerId>,
    ) {
        result
            .validated
            .iter()
            .filter_map(|id| metadatas.remove(id))
            .for_each(|(_, source)| {
                self.add_validated(source);
            });

        result
            .invalidated
            .iter()
            .filter_map(|id| metadatas.remove(id))
            .for_each(|(_, source)| {
                self.add_invalidated(source);
            });
    }
}

impl Mode {
    pub fn is_archive(&self) -> bool {
        matches!(self, Mode::Archive)
    }

    pub fn is_normal(&self) -> bool {
        matches!(self, Mode::Normal(_))
    }
}

impl State {
    pub fn update_tip(&mut self, cumulative_weight: Weight, hash: Multihash) {
        let new_tip = (cumulative_weight, hash);
        let current_tip = (self.tip_cumulative_weight, self.tip_hash);

        if new_tip > current_tip {
            self.tip_cumulative_weight = cumulative_weight;
            self.tip_hash = hash;
        }
    }

    pub fn update_checkpoint(&mut self, weight: Weight, total_weight: Weight, hash: Multihash) {
        if (self.current_checkpoint_total_weight as f64) * 0.67 < weight as f64 {
            self.current_checkpoint_total_weight = total_weight;
            self.checkpoints.push(hash);
        }
    }

    pub fn checkpoint_hash(&self) -> Multihash {
        *self
            .checkpoints
            .last()
            .expect("Checkpoint hash should exist in the state")
    }
}

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey, mode: Mode) -> Self {
        let root_block = block::Builder::new()
            .with_parent_hash(Multihash::default())
            .with_proposer_pk(sk.public_key())
            .with_proposer_weight(0)
            .build();

        let hash = root_block.hash::<H>();

        let state = State {
            tip_cumulative_weight: 0,
            tip_hash: hash,
            current_checkpoint_total_weight: 0,
            checkpoints: vec![hash],
        };

        let state = Arc::new(ParkingRwLock::new(state));
        let mode = Arc::new(mode);
        let root = BlockNode::new(root_block, None, state.clone(), mode.clone());

        let block_dag = Dag::with_root(root.clone());
        let block_dag = ParkingRwLock::new(block_dag);
        let proposal_dags = DashMap::new();

        Self {
            sk,
            block_dag,
            proposal_dags,
            pending_blocks: DashMap::new(),
            invalidated_hashes: DashSet::new(),
            proposal_to_block: DashMap::new(),
            state,
            sources: DashMap::new(),
            mode,
        }
    }

    // pub fn from_sync_state(sk: SecretKey, sync_state: SyncState, mode: Mode) -> Self {
    //     let state = State {
    //         tip_cumulative_weight: sync_state.tip_cumulative_weight,
    //         tip_height: sync_state.tip_block.height,
    //         tip_hash: sync_state.tip_block.hash::<H>(),
    //         checkpoint_total_weight: sync_state.checkpoint_total_weight,
    //         checkpoint_hash: sync_state.checkpoint_block.hash::<H>(),
    //     };
    //
    //     let state = Arc::new(ParkingRwLock::new(state));
    //
    //     let mode = Arc::new(mode);
    //
    //     let root_node =
    //         UnifiedNode::new_block(sync_state.tip_block, None, state.clone(), mode.clone());
    //
    //     let dag = ParkingRwLock::new(Dag::with_root(root_node));
    //
    //     Self {
    //         sk,
    //         dag,
    //         state,
    //         sources: DashMap::new(),
    //         mode,
    //     }
    // }

    pub fn from_other(sk: SecretKey, other: &Self) -> Self {
        let state = other.state.clone();

        let block_dag = other.block_dag.read().clone();
        let proposal_dags = other.proposal_dags.clone();

        Self {
            sk,
            block_dag: ParkingRwLock::new(block_dag),
            proposal_dags,
            pending_blocks: DashMap::new(),
            invalidated_hashes: DashSet::new(),
            proposal_to_block: DashMap::new(),
            state,
            sources: DashMap::new(),
            mode: other.mode.clone(),
        }
    }

    pub fn update_block(
        &self,
        block: Block,
        witness: block::Witness,
        source: PeerId,
    ) -> ProcessResult {
        let hash = block.hash::<H>();

        let mut result = ProcessResult::new();

        if self.invalidated_hashes.contains(&hash)
            || self.invalidated_hashes.contains(&block.parent)
        {
            self.invalidated_hashes.insert(hash);
            result.add_invalidated(source);
            return result;
        }

        if self.block_dag.read().contains(&hash) {
            return result;
        }

        self.sources.insert(hash, source);
        self.pending_blocks.insert(hash, block.parent);

        let dag_res = self.upsert_block_to_proposal_dag(block, witness, &mut result);
        self.process_validation_result(&dag_res, &mut result);

        result
    }

    fn upsert_block_to_proposal_dag(
        &self,
        block: Block,
        witness: block::Witness,
        res: &mut ProcessResult,
    ) -> ValidationResult<UnifiedNode<H>> {
        let ps = self.generate_block_parents(&block, res);
        let mut entry = self.proposal_dags.entry(block.parent).or_default();
        let dag = entry.value_mut();
        let n = UnifiedNode::new_block(block, Some(witness), self.state.clone(), self.mode.clone());
        dag.upsert(n, ps)
    }

    fn generate_block_parents(&self, block: &Block, result: &mut ProcessResult) -> Vec<Multihash> {
        let mut parents = Vec::with_capacity(block.proposals.len());

        let dag = self.proposal_dags.entry(block.parent).or_default();

        block.proposals.iter().for_each(|prop| {
            if !dag.contains(prop) {
                result.add_phantom(*prop);
            }
            parents.push(*prop);
        });

        parents
    }

    fn process_validation_result(
        &self,
        validation_result: &ValidationResult<UnifiedNode<H>>,
        process_result: &mut ProcessResult,
    ) {
        validation_result.validated.iter().for_each(|id| {
            if let Some((id, parent)) = self.pending_blocks.remove(id) {
                let un_node = self
                    .proposal_dags
                    .get_mut(&parent)
                    .expect("Parent DAG should exist")
                    .remove(&id)
                    .expect("Node should exist in the DAG");

                let block_node = un_node
                    .as_block()
                    .expect("Node should be a BlockNode")
                    .clone();

                let _ = self
                    .block_dag
                    .write()
                    .upsert(block_node, std::iter::once(parent));

                let mut dag = self.proposal_dags.entry(id).or_default();
                dag.value_mut().upsert(un_node, std::iter::empty());
            }

            if let Some((_, source)) = self.sources.remove(id) {
                process_result.add_validated(source);
            }
        });

        validation_result.invalidated.iter().for_each(|id| {
            if self.pending_blocks.remove(id).is_some() {
                self.invalidated_hashes.insert(*id);
                self.proposal_dags.remove(id);
                if let Some((_, source)) = self.sources.remove(id) {
                    process_result.add_invalidated(source);
                }
            }
        });
    }

    pub fn update_proposal(
        &self,
        proposal: Proposal,
        witness: proposal::Witness,
        source: PeerId,
    ) -> ProcessResult {
        let mut result = ProcessResult::new();
        let hash = proposal.hash::<H>();

        if self.invalidated_hashes.contains(&hash)
            || self.invalidated_hashes.contains(&proposal.parent_hash)
        {
            self.invalidated_hashes.insert(hash);
            result.add_invalidated(source);
            return result;
        }

        self.sources.insert(hash, source);
        self.proposal_to_block.insert(hash, proposal.parent_hash);

        let dag_result = {
            let mut entry = self.proposal_dags.entry(proposal.parent_hash).or_default();
            let dag = entry.value_mut();
            let parents = proposal.dependencies.iter().cloned().collect::<Vec<_>>();
            let node = UnifiedNode::new_proposal(proposal, witness);
            dag.upsert(node, parents)
        };

        self.process_validation_result(&dag_result, &mut result);

        result
    }

    pub fn tip_trie(&self) -> Trie<H> {
        let tip_hash = self.tip_hash();
        self.block_dag
            .read()
            .get_node(&tip_hash)
            .expect("Tip hash should exist in the DAG")
            .trie
            .read()
            .clone()
    }

    pub fn tip_hash(&self) -> Multihash {
        self.state.read().tip_hash
    }

    pub fn create_and_update_block(
        &self,
        parent: Multihash,
        vdf_proof: Vec<u8>,
    ) -> Option<(Block, block::Witness)> {
        let ids = self.proposal_dags.get(&parent)?.get_leaf_nodes(&parent)?;

        if ids.is_empty() {
            return None;
        }

        let (parent_trie, parent_hash) = {
            let dag = self.block_dag.read();
            let p = dag.get_node(&parent)?;
            let trie = p.trie.read().clone();
            (trie, p.block.hash::<H>())
        };

        let pk_hash = self.sk.public_key().to_hash::<H>();

        let weight = {
            let key = pk_hash.to_bytes();
            parent_trie.get(&key).map_or(0, |r| r.weight)
        };

        let block = block::Builder::new()
            .with_parent_hash(parent_hash)
            .with_proposer_pk(self.sk.public_key())
            .with_proposer_weight(weight)
            .with_proposals(ids)
            .build();

        let block_hash = block.hash::<H>();

        let sig = self.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&parent_trie);
        let witness = block::Witness::new(sig, proofs, vdf_proof);
        let peer_id = PeerId::from_multihash(pk_hash).unwrap();

        self.update_block(block.clone(), witness.clone(), peer_id);

        Some((block, witness))
    }

    pub fn get_proposals<I>(&self, ids: I) -> Vec<(Proposal, proposal::Witness)>
    where
        I: IntoIterator<Item = Multihash>,
    {
        let mut iter = ids.into_iter().peekable();

        let Some(first) = iter.peek() else {
            return Vec::new();
        };

        let mut proposals = Vec::new();

        let Some(dag) = self.proposal_dags.get(first) else {
            return proposals;
        };

        iter.for_each(|id| {
            if let Some(UnifiedNode::Proposal(node)) = dag.get_node(&id) {
                let proposal = node.proposal.clone();
                let witness = node.witness.clone();
                proposals.push((proposal, witness));
            }
        });

        proposals
    }

    pub fn generate_sync_state<I>(&self, keys: I) -> Option<SyncState>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        if self.mode.is_normal() {
            return None;
        }

        let (tip_trie, tip_block, tip_cumulative_weight) = {
            let dag_read = self.block_dag.read();
            let tip_node = dag_read
                .get_node(&self.tip_hash())
                .expect("Tip hash should exist in the DAG");
            let tip_trie = tip_node.trie.read().clone();
            let block = tip_node.block.clone();
            let cum_weight = self.state.read().tip_cumulative_weight;

            (tip_trie, block, cum_weight)
        };

        let (checkpoint_block, checkpoint_total_weight) = {
            let state_read = self.state.read();
            let checkpoint_hash = state_read.checkpoint_hash();
            let dag_read = self.block_dag.read();

            let c = dag_read
                .get_node(&checkpoint_hash)
                .expect("Checkpoint hash should exist in the DAG");

            (c.block.clone(), state_read.current_checkpoint_total_weight)
        };

        let tip_guide = tip_trie.generate_guide(keys)?;

        Some(SyncState {
            tip_block,
            tip_cumulative_weight,
            checkpoint_block,
            checkpoint_total_weight,
            tip_guide,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{block, proposal},
        crypto::SecretKey,
    };
    use libp2p::PeerId;
    use vdf::VDFParams;

    type TestHasher = sha2::Sha256;

    const VDF_PARAMS: vdf::WesolowskiVDFParams = vdf::WesolowskiVDFParams(1024);
    const VDF_DIFFICULTY: u64 = 1;

    #[test]
    fn update_proposal() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let tree = Tree::<TestHasher>::empty(sk.clone(), Mode::Archive);

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(pk)
            .build()
            .expect("Failed to build proposal");

        let hash = prop.hash::<TestHasher>();

        let sig = sk.sign(&hash.to_bytes());
        let proofs = prop.generate_proofs(&tree.tip_trie());
        let vdf_proof = vec![];

        let witness = proposal::Witness::new(sig, proofs, vdf_proof);

        let source = PeerId::random();

        let result = tree.update_proposal(prop, witness, source);

        assert_eq!(result.validated.len(), 1);
        assert_eq!(result.validated[0], source);
        assert!(result.invalidated.is_empty());
    }

    #[test]
    fn update_block() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let tree = Tree::<TestHasher>::empty(sk, Mode::Archive);

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(pk.clone())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let hash = prop.hash::<TestHasher>();

        tree.update_proposal(prop.clone(), witness, PeerId::random());

        let block = block::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposals([hash])
            .with_proposer_pk(pk)
            .with_proposer_weight(0)
            .build();

        let block_hash = block.hash::<TestHasher>();

        let sig = tree.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&tree.tip_trie());
        let vdf_proof = vec![];

        let witness = block::Witness::new(sig, proofs, vdf_proof);

        let source = PeerId::random();

        let result = tree.update_block(block, witness, source);

        assert_eq!(result.validated.len(), 1);
        assert_eq!(result.validated[0], source);
        assert!(result.invalidated.is_empty());
    }
}
