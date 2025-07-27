use std::sync::Arc;

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

pub struct Tree<H: Hasher> {
    sk: SecretKey,
    dag: ParkingRwLock<Dag<UnifiedNode<H>>>,
    tip: Arc<ParkingRwLock<(Weight, u64, Multihash)>>,
    checkpoint: Arc<ParkingRwLock<(Weight, Multihash)>>,
    sources: DashMap<Multihash, PeerId>,
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

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey) -> Self {
        let root_block = block::Builder::new()
            .with_parent_hash(Multihash::default())
            .with_height(0)
            .with_proposer_pk(sk.public_key())
            .with_proposer_weight(0)
            .build();

        let hash = root_block.hash::<H>();

        let tip = Arc::new(ParkingRwLock::new((0, 0, hash)));
        let checkpoint = Arc::new(ParkingRwLock::new((0, hash)));

        let sig = sk.sign(&hash.to_bytes());
        let proofs = root_block.generate_proofs(&Trie::<H>::empty());
        let witness = block::Witness::new(sig, proofs, vec![]);

        let root_node =
            UnifiedNode::new_block(root_block, witness, tip.clone(), checkpoint.clone());

        Self {
            sk,
            dag: ParkingRwLock::new(Dag::with_root(root_node)),
            tip,
            checkpoint,
            sources: DashMap::new(),
        }
    }

    pub fn from_other(sk: SecretKey, other: &Self) -> Self {
        let tip = Arc::clone(&other.tip);
        let checkpoint = Arc::clone(&other.checkpoint);

        let dag = ParkingRwLock::new(other.dag.read().clone());

        Self {
            sk,
            dag,
            tip,
            checkpoint,
            sources: DashMap::new(),
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
            UnifiedNode::new_block(block, witness, self.tip.clone(), self.checkpoint.clone());

        let dag_result = {
            let mut dag_write = self.dag.write();
            dag_write.upsert(node, parent_ids)
        };

        result.merge_from_validation_result(&dag_result, &self.sources);

        result
    }

    fn checkpoint_height(&self) -> u64 {
        let checkpoint = self.checkpoint.read();

        self.dag
            .read()
            .get_node(&checkpoint.1)
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
        self.tip.read().2
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
        let tree = Tree::<TestHasher>::empty(sk.clone());

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
        let tree = Tree::<TestHasher>::empty(sk);

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
