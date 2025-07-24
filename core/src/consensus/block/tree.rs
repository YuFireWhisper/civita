use std::{collections::BTreeMap, sync::Arc};

use dashmap::DashMap;
use derivative::Derivative;
use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            self,
            tree::{block_node::BlockNode, proposal_node::ProposalNode},
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::trie::{Trie, Weight},
};

mod block_node;
pub mod dag;
mod proposal_node;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
pub enum State {
    #[default]
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug)]
#[derive(Default)]
pub struct ProcessResult {
    pub validated_msgs: Vec<(MessageId, PeerId)>,
    pub invalidated_msgs: Vec<(MessageId, PeerId)>,
}

#[derive(Clone)]
#[derive(Debug)]
pub struct Metadata {
    pub msg_id: MessageId,
    pub source: PeerId,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Storage<H> {
    blocks: DashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,
    proposals: DashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,
    tips: ParkingRwLock<BTreeMap<(Weight, u64), Multihash>>,
    checkpoints: ParkingRwLock<Vec<Multihash>>,
}

pub struct Tree<H> {
    storage: Storage<H>,
    threshold: f64,
    sk: SecretKey,
}

impl State {
    pub fn is_valid(&self) -> bool {
        matches!(self, State::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, State::Invalid)
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, State::Pending)
    }
}

impl Metadata {
    pub fn new(msg_id: MessageId, source: PeerId) -> Self {
        Self { msg_id, source }
    }
}

impl ProcessResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_validated(&mut self, msg_id: MessageId, source: PeerId) {
        self.validated_msgs.push((msg_id, source));
    }

    pub fn add_invalidated(&mut self, msg_id: MessageId, source: PeerId) {
        self.invalidated_msgs.push((msg_id, source));
    }

    pub fn merge(&mut self, other: ProcessResult) {
        self.validated_msgs.extend(other.validated_msgs);
        self.invalidated_msgs.extend(other.invalidated_msgs);
    }
}

impl<H: Hasher> Storage<H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_genesis() -> Self {
        let genesis_node = Arc::new(ParkingRwLock::new(BlockNode::new_genesis()));
        let genesis_hash = genesis_node.read().hash().unwrap();

        let blocks = DashMap::new();
        blocks.insert(genesis_hash, genesis_node.clone());

        let mut tips = BTreeMap::new();
        let genesis_weight = genesis_node.read().weight.unwrap();

        tips.insert((genesis_weight, 0), genesis_hash);

        let checkpoints = vec![genesis_hash];

        Self {
            blocks,
            proposals: DashMap::default(),
            tips: ParkingRwLock::new(tips),
            checkpoints: ParkingRwLock::new(checkpoints),
        }
    }
}

impl<H: Hasher> Tree<H> {
    pub fn empty(sk: SecretKey, threshold: f64) -> Self {
        Self {
            storage: Storage::default(),
            sk,
            threshold,
        }
    }

    pub fn with_genesis(sk: SecretKey, threshold: f64) -> Self {
        Self {
            storage: Storage::with_genesis(),
            sk,
            threshold,
        }
    }

    pub fn update_block(
        &self,
        block: Block,
        witness: block::Witness,
        msg_id: MessageId,
        source: PeerId,
    ) -> ProcessResult {
        let hash = block.hash::<H>();
        let parent_hash = block.parent;
        let mut result = ProcessResult::new();

        if self.is_below_checkpoint(&hash) {
            result.add_invalidated(msg_id, source);
            return result;
        }

        let node = self.get_or_insert_missing_block(hash);

        if node.read().is_missing() {
            node.write().set_block_data(block, witness);
            node.write().set_metadata(msg_id.clone(), source);
        }

        if !self.add_block_to_parent(parent_hash, hash, node.clone()) {
            node.write().invalidate_descendants(&mut result);
            return result;
        }

        let proposal_hashes = node
            .read()
            .block
            .as_ref()
            .map_or(vec![], |b| b.proposals.iter().cloned().collect());

        if !proposal_hashes
            .iter()
            .all(|h| self.add_block_to_proposal(*h, hash, node.clone(), &mut result))
        {
            node.write().invalidate_descendants(&mut result);
            return result;
        }

        if let Some(r) = self.try_validate_block(node) {
            result.merge(r);
        }

        result
    }

    fn is_below_checkpoint(&self, block_hash: &Multihash) -> bool {
        self.block_height(block_hash)
            .is_some_and(|height| height < self.checkpoint_height())
    }

    fn checkpoint_height(&self) -> u64 {
        self.storage
            .checkpoints
            .read()
            .last()
            .and_then(|hash| self.block_height(hash))
            .unwrap_or(0)
    }

    fn block_height(&self, block_hash: &Multihash) -> Option<u64> {
        self.storage
            .blocks
            .get(block_hash)
            .and_then(|node| node.read().height())
    }

    fn get_or_insert_missing_block(&self, hash: Multihash) -> Arc<ParkingRwLock<BlockNode<H>>> {
        self.storage
            .blocks
            .entry(hash)
            .or_insert_with(|| Arc::new(ParkingRwLock::new(BlockNode::new_missing())))
            .clone()
    }

    fn add_block_to_parent(
        &self,
        parent_hash: Multihash,
        block_hash: Multihash,
        block: Arc<ParkingRwLock<BlockNode<H>>>,
    ) -> bool {
        let parent_node = self.get_or_insert_missing_block(parent_hash);

        parent_node
            .write()
            .children_blocks
            .entry(block_hash)
            .or_insert_with(|| block.clone());

        block.write().set_parent(parent_node.clone());

        let parent_read = parent_node.read();

        !parent_read.state.is_invalid()
    }

    fn add_block_to_proposal(
        &self,
        prop_hash: Multihash,
        block_hash: Multihash,
        block: Arc<ParkingRwLock<BlockNode<H>>>,
        result: &mut ProcessResult,
    ) -> bool {
        let prop_node = self.get_or_insert_missing_proposal(prop_hash);

        prop_node
            .write()
            .children_blocks
            .entry(block_hash)
            .or_insert_with(|| block.clone());

        let prop_state = prop_node.read().state;

        {
            let mut block_write = block.write();

            block_write
                .proposals
                .entry(prop_hash)
                .or_insert_with(|| prop_node);

            if prop_state.is_valid() {
                block_write.on_proposal_validated(prop_hash, result);
            }
        }

        !prop_state.is_invalid()
    }

    fn get_or_insert_missing_proposal(
        &self,
        hash: Multihash,
    ) -> Arc<ParkingRwLock<ProposalNode<H>>> {
        self.storage
            .proposals
            .entry(hash)
            .or_insert_with(|| Arc::new(ParkingRwLock::new(ProposalNode::new_missing())))
            .clone()
    }

    fn try_validate_block(&self, block: Arc<ParkingRwLock<BlockNode<H>>>) -> Option<ProcessResult> {
        let mut node = block.write();

        if let Some(result) = node.try_validate(false) {
            if node.state == State::Valid {
                let block_hash = node.block.as_ref().unwrap().hash::<H>();
                let weight = node.weight.unwrap();
                let height = node.height().unwrap();
                self.update_tips(block_hash, weight, height);
                self.check_and_create_checkpoint(block_hash, weight);
            }

            return Some(result);
        }

        None
    }

    fn update_tips(&self, hash: Multihash, cumulative_weight: Weight, height: u64) {
        let mut tips = self.storage.tips.write();
        tips.retain(|&w, _| w >= (cumulative_weight, height));
        tips.insert((cumulative_weight, height), hash);
    }

    fn check_and_create_checkpoint(&self, hash: Multihash, weight: Weight) {
        let threshold = self.threshold
            * self.storage.checkpoints.read().last().map_or(0.0, |h| {
                self.storage
                    .blocks
                    .get(h)
                    .and_then(|node| node.read().trie.as_ref().map(|trie| trie.weight() as f64))
                    .unwrap_or(0.0)
            });

        if (weight as f64) < threshold {
            return;
        }

        let mut checkpoints = self.storage.checkpoints.write();
        if checkpoints.last().is_none_or(|last| *last != hash) {
            checkpoints.push(hash);
        }
    }

    pub fn update_proposal(
        &self,
        proposal: Proposal,
        witness: proposal::Witness,
        msg_id: MessageId,
        source: PeerId,
    ) -> ProcessResult {
        let hash = proposal.hash::<H>();
        let parent_hash = proposal.parent_hash;
        let mut result = ProcessResult::new();

        if self.is_below_checkpoint(&hash) {
            result.add_invalidated(msg_id, source);
            return result;
        }

        let node = self.get_or_insert_missing_proposal(hash);

        self.add_proposal_to_parent_block(parent_hash, hash, node.clone());

        if !proposal
            .dependencies
            .iter()
            .all(|dep| self.add_proposal_to_parent_proposal(*dep, hash, node.clone(), &mut result))
        {
            result.add_invalidated(msg_id, source);
            node.write().invalidate_descendants(&mut result);
            return result;
        }

        let mut node_write = node.write();
        node_write.set_proposal_data(proposal, witness);
        node_write.set_metadata(msg_id, source);

        if let Some(r) = node_write.try_validate() {
            result.merge(r);
        }

        result
    }

    fn add_proposal_to_parent_block(
        &self,
        parent_hash: Multihash,
        proposal_hash: Multihash,
        proposal: Arc<ParkingRwLock<ProposalNode<H>>>,
    ) {
        let parent_node = self.get_or_insert_missing_block(parent_hash);

        parent_node
            .write()
            .children_proposals
            .entry(proposal_hash)
            .or_insert_with(|| proposal.clone());

        proposal.write().parent_block = parent_node;
    }

    fn add_proposal_to_parent_proposal(
        &self,
        parent_hash: Multihash,
        proposal_hash: Multihash,
        proposal: Arc<ParkingRwLock<ProposalNode<H>>>,
        result: &mut ProcessResult,
    ) -> bool {
        let parent_node = self.get_or_insert_missing_proposal(parent_hash);

        parent_node
            .write()
            .children_proposals
            .entry(proposal_hash)
            .or_insert_with(|| proposal.clone());

        proposal
            .write()
            .parent_proposals
            .entry(parent_hash)
            .or_insert_with(|| parent_node.clone());

        {
            let mut proposal_write = proposal.write();

            if proposal_write.state.is_valid() {
                proposal_write.on_parent_proposal_validated(parent_hash, result);
            }
        }

        let parent_state = parent_node.read().state;

        !parent_state.is_invalid()
    }

    pub fn update_proposal_client_validation(
        &self,
        proposal_hash: Multihash,
        is_valid: bool,
    ) -> ProcessResult {
        let mut result = ProcessResult::new();

        if let Some(node) = self.get_proposal_node(proposal_hash) {
            if let Some(r) = node.write().set_client_validation(is_valid) {
                result.merge(r);
            }
        }

        result
    }

    fn get_proposal_node(&self, hash: Multihash) -> Option<Arc<ParkingRwLock<ProposalNode<H>>>> {
        self.storage.proposals.get(&hash).map(|n| n.clone())
    }

    pub fn update_proposal_unchecked(&self, proposal: Proposal, witness: proposal::Witness) {
        let hash = proposal.hash::<H>();
        let parent_hash = proposal.parent_hash;

        let weight = proposal
            .verify_proposer_weight::<H>(&witness, self.tip_trie().root_hash())
            .expect("Proposal must have a valid proposer weight");
        let node = ProposalNode::new_valid_uncheck(proposal, witness, weight);
        let node = Arc::new(ParkingRwLock::new(node));

        self.add_proposal_to_parent_block(parent_hash, hash, node.clone());

        self.storage.proposals.insert(hash, node);
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.tip_node()
            .read()
            .trie
            .as_ref()
            .cloned()
            .expect("Tip node must have a trie")
    }

    fn tip_node(&self) -> Arc<ParkingRwLock<BlockNode<H>>> {
        self.storage
            .blocks
            .get(&self.tip_hash())
            .map(|n| n.clone())
            .expect("There must be at least one tip node")
    }

    pub fn tip_hash(&self) -> Multihash {
        self.storage
            .tips
            .read()
            .values()
            .last()
            .cloned()
            .expect("There must be at least one tip")
    }

    pub fn create_and_update_block(
        &self,
        parent: Multihash,
        vdf_proof: Vec<u8>,
    ) -> (Block, block::Witness) {
        let parent_node = self.get_block(&parent).expect("Parent block must exist");

        let node = BlockNode::generate_next(parent_node.clone(), &self.sk, vdf_proof);

        let block = node.block.as_ref().expect("Block must be set").clone();
        let hash = node.hash().unwrap();
        let witenss = node.witness.as_ref().expect("Witness must be set").clone();
        let weight = node.weight.expect("Weight must be set");
        let node_height = node.height().expect("Height must be set");

        let node = Arc::new(ParkingRwLock::new(node));

        parent_node
            .write()
            .children_blocks
            .insert(hash, node.clone());

        self.storage.blocks.insert(hash, node.clone());
        self.update_tips(hash, weight, node_height);
        self.check_and_create_checkpoint(hash, weight);

        (block, witenss)
    }

    fn get_block(&self, hash: &Multihash) -> Option<Arc<ParkingRwLock<BlockNode<H>>>> {
        self.storage.blocks.get(hash).map(|n| n.clone())
    }

    pub fn is_block_proposal_empty(&self, block_hash: &Multihash) -> bool {
        self.get_block(block_hash)
            .is_none_or(|node| node.read().children_proposals.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{block, proposal},
        crypto::SecretKey,
    };
    use libp2p::{gossipsub::MessageId, PeerId};
    use std::collections::HashMap;
    use vdf::{VDFParams, VDF};

    type TestHasher = sha2::Sha256;

    const THRESHOLD: f64 = 0.5;
    const VDF_PARAMS: vdf::WesolowskiVDFParams = vdf::WesolowskiVDFParams(1024);
    const VDF_DIFFICULTY: u64 = 1;
    const MESSAGE_ID_BYTES: &[u8] = b"test_message_id";

    fn create_tree() -> Tree<TestHasher> {
        let sk = SecretKey::random();
        Tree::with_genesis(sk, THRESHOLD)
    }

    #[test]
    fn update_proposal() {
        let tree = create_tree();

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(tree.sk.public_key())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let hash = prop.hash::<TestHasher>();

        let result = tree.update_proposal(prop, witness, msg_id, source);

        assert!(result.validated_msgs.is_empty());
        assert!(result.invalidated_msgs.is_empty());
        assert!(tree
            .storage
            .proposals
            .get(&hash)
            .is_some_and(|n| { n.read().state.is_pending() }));
    }

    #[test]
    fn valid_when_proposal_completed() {
        let tree = create_tree();

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(tree.sk.public_key())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let hash = prop.hash::<TestHasher>();

        tree.update_proposal(prop, witness, msg_id.clone(), source);
        let res = tree.update_proposal_client_validation(hash, true);

        assert_eq!(res.validated_msgs.len(), 1);
        assert_eq!(res.validated_msgs[0], (msg_id, source));
        assert!(res.invalidated_msgs.is_empty());
        assert!(tree
            .storage
            .proposals
            .get(&hash)
            .is_some_and(|n| { n.read().state.is_valid() }));
    }

    #[test]
    fn invalid_when_client_validation_fails() {
        let tree = create_tree();

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(tree.sk.public_key())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let hash = prop.hash::<TestHasher>();

        tree.update_proposal(prop, witness, msg_id.clone(), source);
        let res = tree.update_proposal_client_validation(hash, false);

        assert!(res.validated_msgs.is_empty());
        assert_eq!(res.invalidated_msgs.len(), 1);
        assert_eq!(res.invalidated_msgs[0], (msg_id, source));
        assert!(tree
            .storage
            .proposals
            .get(&hash)
            .is_some_and(|n| { n.read().state.is_invalid() }));
    }

    #[test]
    fn update_block() {
        let tree = create_tree();

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(tree.sk.public_key())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let hash = prop.hash::<TestHasher>();
        tree.update_proposal(prop, witness, msg_id.clone(), source);
        tree.update_proposal_client_validation(hash, true);

        let block = block::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_height(1)
            .with_proposals([hash])
            .with_proposer_pk(tree.sk.public_key())
            .with_proposer_weight(0)
            .build();

        let block_hash = block.hash::<TestHasher>();

        let sig = tree.sk.sign(&block_hash.to_bytes());
        let proofs = block.generate_proofs(&tree.tip_trie());
        let vdf = VDF_PARAMS.new();
        let vdf_proof = vdf
            .solve(&block_hash.to_bytes(), VDF_DIFFICULTY)
            .expect("Failed to solve VDF");

        let witness = block::Witness::new(sig, proofs, vdf_proof);

        // All info is set, so the block should be valid
        let result = tree.update_block(block, witness, msg_id.clone(), source);

        assert_eq!(result.validated_msgs.len(), 1);
        assert_eq!(result.validated_msgs[0], (msg_id, source));
        assert!(result.invalidated_msgs.is_empty());
    }

    #[test]
    fn invalid_if_block_ref_proposal_is_invalid() {
        let tree = create_tree();

        let prop = proposal::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_proposer_pk(tree.sk.public_key())
            .build()
            .expect("Failed to build proposal");

        let vdf = VDF_PARAMS.new();
        let witness = prop
            .generate_witness(&tree.sk, &tree.tip_trie(), &vdf, VDF_DIFFICULTY)
            .expect("Failed to generate witness");

        let msg_id = MessageId::new(MESSAGE_ID_BYTES);
        let source = PeerId::random();

        let hash = prop.hash::<TestHasher>();
        tree.update_proposal(prop, witness, msg_id.clone(), source);
        tree.update_proposal_client_validation(hash, false);

        let block = block::Builder::new()
            .with_parent_hash(tree.tip_hash())
            .with_height(1)
            .with_proposals([hash])
            .with_proposer_pk(tree.sk.public_key())
            .with_proposer_weight(0)
            .build();

        let block_hash = block.hash::<TestHasher>();

        let vdf = VDF_PARAMS.new();
        let vdf_proof = vdf
            .solve(&block_hash.to_bytes(), VDF_DIFFICULTY)
            .expect("Failed to solve VDF");

        let witness = block::Witness::new(
            tree.sk.sign(&block_hash.to_bytes()),
            HashMap::new(),
            vdf_proof,
        );

        let result = tree.update_block(block, witness, msg_id.clone(), source);

        assert!(result.validated_msgs.is_empty());
        assert_eq!(result.invalidated_msgs.len(), 1);
        assert_eq!(result.invalidated_msgs[0], (msg_id, source));
    }
}
