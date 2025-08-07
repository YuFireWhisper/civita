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
                checkpoint::{Checkpoint, EstablishedBlock, UpdateResult},
                dag::{Node, ValidationResult},
                node::{BlockNode, SerializedBlockNode, UnifiedNode},
            },
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::{trie::Trie, Record},
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
pub enum Mode {
    Archive,
    Normal(Vec<Vec<u8>>),
}

pub struct Tree<H: Hasher, T: Record> {
    sk: SecretKey,
    checkpoint: ParkingRwLock<Checkpoint<H, T>>,
    history: DashMap<Multihash, HashMap<Multihash, EstablishedBlock<T>>>,
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

impl<H: Hasher, T: Record> Tree<H, T> {
    pub fn empty(sk: SecretKey, mode: Mode) -> Self {
        let mode = Arc::new(mode);
        let checkpoint = Checkpoint::new_empty(mode.clone());
        let checkpoint = ParkingRwLock::new(checkpoint);

        Self {
            sk,
            checkpoint,
            mode,
            history: DashMap::new(),
            sources: DashMap::new(),
        }
    }

    pub fn from_tip(sk: SecretKey, tip: BlockNode<H, T>, mode: Mode) -> Self {
        let mode = Arc::new(mode);
        let checkpoint = ParkingRwLock::new(Checkpoint::with_root(tip, mode.clone()));

        Self {
            sk,
            checkpoint,
            mode,
            history: DashMap::new(),
            sources: DashMap::new(),
        }
    }

    pub fn from_blocks<I>(sk: SecretKey, blocks: I) -> Option<Self>
    where
        I: IntoIterator<Item = EstablishedBlock<T>>,
    {
        let mode = Arc::new(Mode::Archive);
        let (checkpoint, history) = Checkpoint::from_blocks(blocks)?;

        Some(Self {
            sk,
            checkpoint: ParkingRwLock::new(checkpoint),
            history: history.into_iter().collect(),
            sources: DashMap::new(),
            mode,
        })
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
        let result = {
            let mut checkpoint = self.checkpoint.write();
            checkpoint.update_block(block, witness)
        };
        self.process_result(result)
    }

    pub fn checkpoint_hash(&self) -> Multihash {
        self.checkpoint.read().root_hash()
    }

    fn process_result(&self, mut result: UpdateResult<H, T>) -> ProcessResult {
        if let Some(block) = result.new_checkpoint {
            let original = {
                let n = Checkpoint::with_root(block, self.mode.clone());
                let mut o = self.checkpoint.write();
                std::mem::replace(&mut *o, n)
            };

            if self.mode.is_archive() {
                let hash = original.root_hash();
                let blocks = original.into_blocks();
                self.history.insert(hash, blocks.into_iter().collect());
            }
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
        proposal: Proposal<T>,
        witness: proposal::Witness,
        source: PeerId,
    ) -> ProcessResult {
        if proposal.checkpoint != self.checkpoint_hash() {
            return ProcessResult::new();
        }

        let hash = proposal.hash::<H>();
        self.sources.insert(hash, source);

        let result = {
            let mut checkpoint = self.checkpoint.write();
            checkpoint.update_proposal(proposal, witness)
        };

        self.process_result(result)
    }

    pub fn tip_trie(&self) -> Trie<H, T> {
        self.checkpoint.read().tip_trie()
    }

    pub fn tip_hash(&self) -> Multihash {
        self.checkpoint.read().tip_hash()
    }

    pub fn create_and_update_block(
        &self,
        parent: Multihash,
        vdf_proof: Vec<u8>,
    ) -> Option<(Block, block::Witness)> {
        let (ids, trie) = {
            let checkpoint = self.checkpoint.read();
            let dag = checkpoint.get_proposal_dag(parent)?;
            let ids = dag.get_leaf_nodes();
            let trie = checkpoint.get_trie(&parent)?;
            (ids, trie)
        };

        if ids.is_empty() {
            return None;
        }

        let pk_hash = self.sk.public_key().to_hash::<H>();

        let block = block::Builder::new()
            .with_parent_hash(parent)
            .with_checkpoint(self.checkpoint_hash())
            .with_proposer_pk(self.sk.public_key())
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

    pub fn get_proposals<I>(&self, ids: I) -> Vec<(Proposal<T>, proposal::Witness)>
    where
        I: IntoIterator<Item = Multihash>,
    {
        let mut iter = ids.into_iter().peekable();

        let Some(first) = iter.peek() else {
            return Vec::new();
        };

        let checkpoint = self.checkpoint.read();
        let Some(dag) = checkpoint.get_proposal_dag(*first) else {
            return Vec::new();
        };

        let mut proposals = Vec::new();

        iter.for_each(|id| {
            if let Some(UnifiedNode::Proposal(node)) = dag.get(&id) {
                let proposal = node.proposal.clone();
                let witness = node.witness.clone();
                proposals.push((proposal, witness));
            }
        });

        proposals
    }

    pub fn tip_seralized<I>(&self, keys: I) -> Option<SerializedBlockNode<T>>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        assert!(self.mode.is_archive());

        let checkpoint = self.checkpoint.read();

        if checkpoint.is_empty() {
            return None;
        }

        Some(
            checkpoint
                .tip_node()
                .to_serialized(keys)
                .expect("Failed to serialize tip node"),
        )
    }

    pub fn to_blocks(&self) -> impl IntoIterator<Item = EstablishedBlock<T>> {
        assert!(self.mode.is_archive());

        let mut blocks = Vec::new();

        self.history.iter().for_each(|entry| {
            blocks.extend(entry.value().values().cloned());
        });

        blocks.extend(self.checkpoint.read().to_blocks().into_values());

        blocks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{block, proposal},
        crypto::SecretKey,
        utils::Operation,
    };
    use libp2p::PeerId;
    use vdf::VDFParams;

    type TestHasher = sha2::Sha256;
    type TestTree = Tree<TestHasher, TestRecord>;

    const VDF_PARAMS: vdf::WesolowskiVDFParams = vdf::WesolowskiVDFParams(1024);
    const VDF_DIFFICULTY: u64 = 1;

    #[derive(Clone)]
    #[derive(Debug)]
    #[derive(Eq, PartialEq)]
    #[derive(Serialize)]
    struct TestOperation;

    #[derive(Clone)]
    #[derive(Debug)]
    #[derive(Default)]
    #[derive(Eq, PartialEq)]
    #[derive(Serialize)]
    struct TestRecord;

    impl Record for TestRecord {
        type Operation = TestOperation;
        type Weight = u64;

        fn try_apply(&mut self, _: Self::Operation) -> bool {
            true
        }

        fn weight(&self) -> Self::Weight {
            0
        }
    }

    impl Operation for TestOperation {
        fn is_empty(&self) -> bool {
            false
        }

        fn is_order_dependent(&self, _: &[u8]) -> bool {
            false
        }
    }

    #[test]
    fn update_proposal() {
        let sk = SecretKey::random_secp256k1();
        let pk = sk.public_key();
        let tree = TestTree::empty(sk.clone(), Mode::Archive);

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_checkpoint(tree.checkpoint_hash())
            .with_operation(vec![1, 2, 3], TestOperation)
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
        let sk = SecretKey::random_secp256k1();
        let pk = sk.public_key();
        let tree = TestTree::empty(sk, Mode::Archive);

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_checkpoint(tree.checkpoint_hash())
            .with_operation(vec![1, 2, 3], TestOperation)
            .with_proposer_pk(pk.clone())
            .build()
            .expect("Failed to build proposal");

        let proofs = prop.generate_proofs(&tree.tip_trie());

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness::<TestHasher>(&tree.sk, proofs, &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let hash = prop.hash::<TestHasher>();

        tree.update_proposal(prop.clone(), witness, PeerId::random());

        let block = block::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_checkpoint(tree.checkpoint_hash())
            .with_proposals([hash])
            .with_proposer_pk(pk)
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
