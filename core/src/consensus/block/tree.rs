use std::{collections::HashMap, sync::Arc};

use civita_serialize_derive::Serialize;
use dashmap::DashMap;
use libp2p::PeerId;
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            self,
            tree::{
                dag::{Dag, Node, ValidationResult},
                node::UnifiedNode,
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

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
struct State {
    tip_cumulative_weight: Weight,
    tip_height: u64,
    tip_hash: Multihash,

    checkpoint_total_weight: Weight,
    checkpoint_hash: Multihash,
}

pub struct Tree<H: Hasher> {
    sk: SecretKey,
    dag: ParkingRwLock<Dag<UnifiedNode<H>>>,
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
    pub fn update_tip(&mut self, cumulative_weight: Weight, height: u64, hash: Multihash) {
        let new_tip = (cumulative_weight, height, hash);
        let current_tip = (self.tip_cumulative_weight, self.tip_height, self.tip_hash);

        if new_tip > current_tip {
            self.tip_cumulative_weight = cumulative_weight;
            self.tip_height = height;
            self.tip_hash = hash;
        }
    }

    pub fn update_checkpoint(&mut self, weight: Weight, total_weight: Weight, hash: Multihash) {
        if (self.checkpoint_total_weight as f64) * 0.67 < weight as f64 {
            self.checkpoint_total_weight = total_weight;
            self.checkpoint_hash = hash;
        }
    }

    pub fn checkpoint_hash(&self) -> Multihash {
        self.checkpoint_hash
    }
}

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey, mode: Mode) -> Self {
        let root_block = block::Builder::new()
            .with_parent_hash(Multihash::default())
            .with_height(0)
            .with_proposer_pk(sk.public_key())
            .with_proposer_weight(0)
            .build();

        let hash = root_block.hash::<H>();

        let state = State {
            tip_cumulative_weight: 0,
            tip_height: 0,
            tip_hash: hash,
            checkpoint_total_weight: 0,
            checkpoint_hash: hash,
        };
        let state = Arc::new(ParkingRwLock::new(state));

        let mode = Arc::new(mode);

        let root_node = UnifiedNode::new_block(root_block, None, state.clone(), mode.clone());

        Self {
            sk,
            dag: ParkingRwLock::new(Dag::with_root(root_node)),
            state,
            sources: DashMap::new(),
            mode,
        }
    }

    pub fn from_sync_state(sk: SecretKey, sync_state: SyncState, mode: Mode) -> Self {
        let state = State {
            tip_cumulative_weight: sync_state.tip_cumulative_weight,
            tip_height: sync_state.tip_block.height,
            tip_hash: sync_state.tip_block.hash::<H>(),
            checkpoint_total_weight: sync_state.checkpoint_total_weight,
            checkpoint_hash: sync_state.checkpoint_block.hash::<H>(),
        };

        let state = Arc::new(ParkingRwLock::new(state));

        let mode = Arc::new(mode);

        let root_node =
            UnifiedNode::new_block(sync_state.tip_block, None, state.clone(), mode.clone());

        let dag = ParkingRwLock::new(Dag::with_root(root_node));

        Self {
            sk,
            dag,
            state,
            sources: DashMap::new(),
            mode,
        }
    }

    pub fn from_other(sk: SecretKey, other: &Self) -> Self {
        let state = other.state.clone();
        let dag = ParkingRwLock::new(other.dag.read().clone());

        Self {
            sk,
            dag,
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

        if self.dag.read().contains(&hash) {
            return result;
        }

        if block.height <= self.checkpoint_height() {
            result.add_invalidated(source);
            return result;
        }

        self.sources.insert(hash, source);

        let mut parent_ids = Vec::with_capacity(block.proposals.len() + 1);
        parent_ids.push(block.parent);

        block.proposals.iter().for_each(|p| {
            parent_ids.push(*p);

            if !self.dag.read().contains(p) {
                result.add_phantom(*p);
            }
        });

        let node =
            UnifiedNode::new_block(block, Some(witness), self.state.clone(), self.mode.clone());

        let dag_result = {
            let mut dag_write = self.dag.write();
            dag_write.upsert(node, parent_ids)
        };

        result.merge_from_validation_result(&dag_result, &self.sources);

        result
    }

    fn checkpoint_height(&self) -> u64 {
        let hash = self.state.read().checkpoint_hash();

        self.dag
            .read()
            .get_node(&hash)
            .expect("Checkpoint hash should exist in the DAG")
            .as_block()
            .expect("Checkpoint node should be a block")
            .height()
    }

    pub fn update_proposal(
        &self,
        proposal: Proposal,
        witness: proposal::Witness,
        source: PeerId,
    ) -> ProcessResult {
        let hash = proposal.hash::<H>();

        let mut result = ProcessResult::new();

        if self.dag.read().contains(&hash) {
            return result;
        }

        if self
            .block_height(&proposal.parent_hash)
            .is_some_and(|height| height < self.checkpoint_height())
        {
            result.add_invalidated(source);
            return result;
        }

        self.sources.insert(hash, source);

        let parent_hash = proposal.parent_hash;
        let node = UnifiedNode::new_proposal(proposal, witness);

        let result = self.dag.write().upsert(node, vec![parent_hash]);

        ProcessResult::from_validation_result(&result, &self.sources)
    }

    fn block_height(&self, hash: &Multihash) -> Option<u64> {
        self.dag
            .read()
            .get_node(hash)
            .and_then(|n| n.as_block().map(|b| b.height()))
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.dag
            .read()
            .get_node(&self.tip_hash())
            .expect("Tip hash should exist in the DAG")
            .as_block()
            .expect("Tip node should be a block")
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
        let prop_ids = self.dag.read().get_leaf_nodes(&parent)?;

        if prop_ids.is_empty() {
            return None;
        }

        let dag_read = self.dag.read();
        let parent_node = dag_read.get_node(&parent)?.as_block()?;

        let weight = {
            let key = self.sk.public_key().to_hash::<H>().to_bytes();
            parent_node.trie.read().get(&key).map_or(0, |r| r.weight)
        };

        let block = block::Builder::new()
            .with_parent_block::<H>(&parent_node.block)
            .with_proposer_pk(self.sk.public_key())
            .with_proposer_weight(weight)
            .with_proposals(prop_ids)
            .build();

        let block_hash = block.hash::<H>();

        let sig = self.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&parent_node.trie.read());
        let witness = block::Witness::new(sig, proofs, vdf_proof);

        drop(dag_read);

        self.update_block(
            block.clone(),
            witness.clone(),
            PeerId::from_multihash(self.sk.public_key().to_hash::<H>()).unwrap(),
        );

        Some((block, witness))
    }

    pub fn get_proposals<I>(&self, ids: I) -> Vec<(Proposal, proposal::Witness)>
    where
        I: IntoIterator<Item = Multihash>,
    {
        let dag_read = self.dag.read();
        ids.into_iter()
            .filter_map(|id| dag_read.get_node(&id))
            .filter_map(|node| node.as_proposal())
            .map(|prop_node| (prop_node.proposal.clone(), prop_node.witness.clone()))
            .collect()
    }

    pub fn generate_sync_state<I>(&self, keys: I) -> Option<SyncState>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        if self.mode.is_normal() {
            return None;
        }

        let dag_read = self.dag.read();
        let tip_node = dag_read
            .get_node(&self.tip_hash())
            .expect("Tip hash should exist in the DAG")
            .as_block()
            .expect("Tip node should be a block");
        let tip_trie = tip_node.trie.read().clone();
        let tip_block = tip_node.block.clone();
        let tip_cumulative_weight = self.state.read().tip_cumulative_weight;

        let checkpoint_node = dag_read
            .get_node(&self.state.read().checkpoint_hash())
            .expect("Checkpoint hash should exist in the DAG")
            .as_block()
            .expect("Checkpoint node should be a block");
        let checkpoint_block = checkpoint_node.block.clone();
        let checkpoint_total_weight = self.state.read().checkpoint_total_weight;

        drop(dag_read);

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
            .with_height(1)
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
