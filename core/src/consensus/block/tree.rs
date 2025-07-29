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
                checkpoint::{Checkpoint, UpdateResult},
                dag::{Node, ValidationResult},
                node::{BlockNode, UnifiedNode},
            },
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::trie::{Trie, Weight},
};

mod checkpoint;
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
    tip_guide: HashMap<Multihash, Vec<u8>>,
}

pub enum Mode {
    Archive,
    Normal(Vec<Vec<u8>>),
}

pub struct Tree<H: Hasher> {
    sk: SecretKey,
    checkpoints: ParkingRwLock<Vec<Checkpoint<H>>>,
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

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey, mode: Mode) -> Self {
        let root_block = block::Builder::new()
            .with_parent_hash(Multihash::default())
            .with_proposer_pk(sk.public_key())
            .with_proposer_weight(0)
            .build();

        let mode = Arc::new(mode);
        let block_node = BlockNode::new(root_block, None, mode.clone());

        let checkpoint = Checkpoint::new(block_node, mode.clone());
        let checkpoints = ParkingRwLock::new(vec![checkpoint]);

        Self {
            sk,
            checkpoints,
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

    pub fn from_other(_: SecretKey, _: &Self) -> Self {
        unimplemented!("Tree::from_other is not implemented yet");
    }

    pub fn update_block(
        &self,
        block: Block,
        witness: block::Witness,
        source: PeerId,
    ) -> ProcessResult {
        if block.checkpoint != self.checkpoint_hash() {
            return ProcessResult::new();
        }

        let hash = block.hash::<H>();
        self.sources.insert(hash, source);
        let mut checkpoints = self.checkpoints.write();
        let checkpoint = checkpoints.last_mut().expect("Checkpoint should exist");
        let result = checkpoint.update_block(block, witness);
        self.process_result(result)
    }

    fn checkpoint_hash(&self) -> Multihash {
        self.checkpoints
            .read()
            .last()
            .expect("Checkpoint should exist")
            .root_hash()
    }

    fn process_result(&self, mut result: UpdateResult<H>) -> ProcessResult {
        if let Some(block) = result.new_checkpoint {
            let checkpoint = Checkpoint::new(block, self.mode.clone());
            self.checkpoints.write().push(checkpoint);
        }

        let mut process_result = ProcessResult::new();

        result.validated.iter().for_each(|id| {
            if let Some((_, source)) = self.sources.remove(id) {
                process_result.add_validated(source);
            }
        });

        result.invalidated.iter().for_each(|id| {
            if let Some((_, source)) = self.sources.remove(id) {
                process_result.add_invalidated(source);
            }
        });

        process_result.phantoms = std::mem::take(&mut result.phantoms);
        process_result
    }

    pub fn update_proposal(
        &self,
        proposal: Proposal,
        witness: proposal::Witness,
        source: PeerId,
    ) -> ProcessResult {
        if proposal.checkpoint != self.checkpoint_hash() {
            return ProcessResult::new();
        }

        let hash = proposal.hash::<H>();
        self.sources.insert(hash, source);
        let mut checkpoints = self.checkpoints.write();
        let checkpoint = checkpoints.last_mut().expect("Checkpoint should exist");
        let result = checkpoint.update_proposal(proposal, witness);
        self.process_result(result)
    }

    pub fn tip_trie(&self) -> Trie<H> {
        let checkpoints = self.checkpoints.read();
        checkpoints
            .last()
            .expect("Checkpoint should exist")
            .tip_trie()
    }

    pub fn tip_hash(&self) -> Multihash {
        let checkpoints = self.checkpoints.read();
        checkpoints
            .last()
            .expect("Checkpoint should exist")
            .tip_hash()
    }

    pub fn create_and_update_block(
        &self,
        parent: Multihash,
        vdf_proof: Vec<u8>,
    ) -> Option<(Block, block::Witness)> {
        let (ids, trie) = {
            let checkpoints = self.checkpoints.read();
            let checkpoint = checkpoints.last().expect("Checkpoint should exist");
            let dag = checkpoint.get_proposal_dag(parent)?;
            let ids = dag.get_leaf_nodes(&parent)?;
            let trie = checkpoint.parent_trie(&parent)?;
            (ids, trie)
        };

        if ids.is_empty() {
            return None;
        }

        let pk_hash = self.sk.public_key().to_hash::<H>();

        let weight = {
            let key = pk_hash.to_bytes();
            trie.get(&key).map_or(0, |r| r.weight)
        };

        let block = block::Builder::new()
            .with_parent_hash(parent)
            .with_proposer_pk(self.sk.public_key())
            .with_proposer_weight(weight)
            .with_proposals(ids)
            .build();

        let block_hash = block.hash::<H>();

        let sig = self.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&trie);
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

        let checkpoints = self.checkpoints.read();
        let dag = checkpoints
            .last()
            .expect("Checkpoint should exist")
            .get_proposal_dag(*first)
            .expect("Proposal DAG should exist");

        let mut proposals = Vec::new();

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

        let (tip_trie, tip_block, tip_cumulative_weight, checkpoint_block) = {
            let checkpoints = self.checkpoints.read();
            let checkpoint = checkpoints.last().expect("Checkpoint should exist");
            let tip_trie = checkpoint.tip_trie();
            let tip_block = checkpoint.tip_block().clone();
            let tip_cum_weight = checkpoint.tip_cumulative_weight();
            let checkpoint_block = checkpoint.root_block().clone();
            (tip_trie, tip_block, tip_cum_weight, checkpoint_block)
        };

        let tip_guide = tip_trie.generate_guide(keys)?;

        Some(SyncState {
            tip_block,
            tip_cumulative_weight,
            checkpoint_block,
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
