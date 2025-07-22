use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use derivative::Derivative;
use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            tree::{block_node::BlockNode, proposal_node::ProposalNode},
            Block,
        },
        proposal::Proposal,
    },
    crypto::{Hasher, Multihash, PublicKey},
    utils::trie::{Trie, Weight},
};

mod block_node;
mod proposal_node;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum State {
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug)]
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
    blocks: ParkingRwLock<HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>>,
    proposals: ParkingRwLock<HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>>,

    tips: ParkingRwLock<BTreeMap<Weight, Multihash>>,

    checkpoints: ParkingRwLock<Vec<Multihash>>,

    genesis_hash: Option<Multihash>,
}

pub struct Tree<H> {
    storage: Storage<H>,
    threshold: f64,
}

impl State {
    pub fn is_valid(&self) -> bool {
        matches!(self, State::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, State::Invalid)
    }
}

impl Metadata {
    pub fn new(msg_id: MessageId, source: PeerId) -> Self {
        Self { msg_id, source }
    }
}

impl ProcessResult {
    pub fn new() -> Self {
        Self {
            validated_msgs: Vec::new(),
            invalidated_msgs: Vec::new(),
        }
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

    pub fn with_genesis(genesis_block: Block) -> Self {
        let genesis_hash = genesis_block.hash::<H>();
        let genesis_node = Arc::new(ParkingRwLock::new(BlockNode::new_genesis(genesis_block)));

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis_node.clone());

        let mut tips = BTreeMap::new();
        tips.insert(genesis_node.read().weight, genesis_hash);

        let checkpoints = vec![genesis_hash];

        Self {
            blocks: ParkingRwLock::new(blocks),
            proposals: ParkingRwLock::new(HashMap::new()),
            tips: ParkingRwLock::new(tips),
            checkpoints: ParkingRwLock::new(checkpoints),
            genesis_hash: Some(genesis_hash),
        }
    }
}

impl<H: Hasher> Tree<H> {
    #[allow(dead_code)]
    pub fn empty(threshold: f64) -> Self {
        Self {
            storage: Storage::default(),
            threshold,
        }
    }

    pub fn with_genesis(genesis_block: Block, threshold: f64) -> Self {
        Self {
            storage: Storage::with_genesis(genesis_block),
            threshold,
        }
    }

    #[allow(dead_code)]
    pub fn update_block(
        &self,
        block: Block,
        proofs: HashMap<Multihash, Vec<u8>>,
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

        let node = {
            let mut blocks = self.storage.blocks.write();
            blocks
                .entry(hash)
                .or_insert_with(|| Arc::new(ParkingRwLock::new(BlockNode::new_missing())))
                .clone()
        };

        if !self.add_block_to_parent(parent_hash, hash, node.clone()) {
            result.add_invalidated(msg_id, source);
            node.write().invalidate_descendants(&mut result);
            return result;
        }

        if !block
            .proposals
            .iter()
            .all(|child| self.add_block_to_proposal(hash, *child, node.clone()))
        {
            result.add_invalidated(msg_id, source);
            node.write().invalidate_descendants(&mut result);
            return result;
        }

        node.write().set_block_data(block, proofs, msg_id, source);

        if let Some(r) = self.try_validate_block(node.clone()) {
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
            .and_then(|hash| {
                self.storage
                    .blocks
                    .read()
                    .get(hash)
                    .map(|node| node.read().block.as_ref().map_or(0, |b| b.height))
            })
            .unwrap_or(0)
    }

    fn block_height(&self, block_hash: &Multihash) -> Option<u64> {
        self.storage
            .blocks
            .read()
            .get(block_hash)
            .and_then(|node| node.read().block.as_ref().map(|b| b.height))
    }

    fn add_block_to_parent(
        &self,
        parent_hash: Multihash,
        block_hash: Multihash,
        block: Arc<ParkingRwLock<BlockNode<H>>>,
    ) -> bool {
        let parent_node = self
            .storage
            .blocks
            .write()
            .entry(parent_hash)
            .or_insert_with(|| Arc::new(ParkingRwLock::new(BlockNode::new_missing())))
            .clone();

        parent_node
            .write()
            .children_blocks
            .entry(block_hash)
            .or_insert_with(|| block.clone());

        let is_not_invalid = parent_node.read().state != State::Invalid;

        block.write().parent = Some(parent_node.clone());

        is_not_invalid
    }

    fn add_block_to_proposal(
        &self,
        prop_hash: Multihash,
        block_hash: Multihash,
        block: Arc<ParkingRwLock<BlockNode<H>>>,
    ) -> bool {
        let prop_node = self
            .storage
            .proposals
            .read()
            .get(&prop_hash)
            .cloned()
            .unwrap_or_else(|| {
                Arc::new(ParkingRwLock::new(ProposalNode::new_missing(Arc::new(
                    ParkingRwLock::new(BlockNode::new_missing()),
                ))))
            });

        prop_node
            .write()
            .child_blocks
            .entry(block_hash)
            .or_insert_with(|| block.clone());

        let is_not_invalid = prop_node.read().state != State::Invalid;

        block
            .write()
            .proposals
            .entry(prop_hash)
            .or_insert_with(|| Some(prop_node));

        is_not_invalid
    }

    fn try_validate_block(&self, block: Arc<ParkingRwLock<BlockNode<H>>>) -> Option<ProcessResult> {
        let mut node = block.write();

        if let Some(result) = node.try_validate() {
            if node.state == State::Valid {
                let block_hash = node.block.as_ref().unwrap().hash::<H>();
                self.update_tips(block_hash, node.weight);
                self.check_and_create_checkpoint(block_hash, node.weight);
            }

            return Some(result);
        }

        None
    }

    fn update_tips(&self, hash: Multihash, weight: Weight) {
        let mut tips = self.storage.tips.write();
        tips.retain(|&w, _| w >= weight);
        tips.insert(weight, hash);
    }

    fn check_and_create_checkpoint(&self, hash: Multihash, weight: Weight) {
        let threshold = self.threshold
            * self.storage.checkpoints.read().last().map_or(0.0, |h| {
                self.storage
                    .blocks
                    .read()
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

    #[allow(dead_code)]
    pub fn update_proposal(
        &self,
        proposal: Proposal,
        proofs: HashMap<Multihash, Vec<u8>>,
        msg_id: MessageId,
        source: PeerId,
    ) -> ProcessResult {
        let hash = proposal.hash::<H>();
        let parent_hash = proposal.parent;
        let mut result = ProcessResult::new();

        if self.is_below_checkpoint(&hash) {
            result.add_invalidated(msg_id, source);
            return result;
        }

        let mut props = self.storage.proposals.write();
        let prop = props.entry(hash).or_insert_with(|| {
            Arc::new(ParkingRwLock::new(ProposalNode::new_missing(Arc::new(
                ParkingRwLock::new(BlockNode::new_missing()),
            ))))
        });

        self.add_proposal_to_parent(parent_hash, hash, prop.clone());

        prop.write()
            .set_proposal_data(proposal, proofs, msg_id, source);

        if let Some(r) = prop.write().try_validate() {
            result.merge(r);
        }

        result
    }

    fn add_proposal_to_parent(
        &self,
        parent_hash: Multihash,
        proposal_hash: Multihash,
        proposal: Arc<ParkingRwLock<ProposalNode<H>>>,
    ) {
        let parent_block = self
            .storage
            .blocks
            .write()
            .entry(parent_hash)
            .or_insert_with(|| Arc::new(ParkingRwLock::new(BlockNode::new_missing())))
            .clone();

        parent_block
            .write()
            .children_proposals
            .entry(proposal_hash)
            .or_insert_with(|| proposal.clone());

        proposal.write().parent_block = parent_block;
    }

    #[allow(dead_code)]
    pub fn update_proposal_client_validation(
        &self,
        proposal_hash: Multihash,
        is_valid: bool,
    ) -> ProcessResult {
        let mut result = ProcessResult::new();

        if let Some(proposal_node) = self.storage.proposals.read().get(&proposal_hash).cloned() {
            if let Some(r) = proposal_node.write().set_client_validation(is_valid) {
                result.merge(r);
            }
        }

        result
    }

    pub fn create_and_update_block(
        &self,
        proposer_pk: PublicKey,
    ) -> (Block, HashMap<Multihash, Vec<u8>>) {
        let tip_hash = {
            self.storage
                .tips
                .read()
                .values()
                .last()
                .cloned()
                .expect("There must be at least one tip")
        };

        let tip_node = self
            .storage
            .blocks
            .read()
            .get(&tip_hash)
            .cloned()
            .expect("Tip must exist");

        let (node, proofs) =
            BlockNode::generate(tip_node.clone(), proposer_pk).expect("Failed to generate block");
        let block = node.block.as_ref().expect("Block must be set").clone();
        let hash = node.hash().unwrap();
        let node = Arc::new(ParkingRwLock::new(node));

        tip_node.write().children_blocks.insert(hash, node.clone());
        node.read().proposals.values().flatten().for_each(|prop| {
            prop.write().child_blocks.insert(hash, node.clone());
        });

        self.storage.blocks.write().insert(hash, node.clone());
        self.update_tips(hash, node.read().weight);
        self.check_and_create_checkpoint(hash, node.read().weight);

        (block, proofs)
    }

    pub fn tip_hash(&self) -> Option<Multihash> {
        self.storage.tips.read().values().last().cloned()
    }

    pub fn tip_trie(&self) -> Trie<H> {
        self.tip_hash()
            .and_then(|hash| {
                self.storage
                    .blocks
                    .read()
                    .get(&hash)
                    .map(|node| node.read().trie.clone())
            })
            .flatten()
            .expect("Tip must have a trie")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{
            block::{self, Block},
            proposal::{self, Diff, Proposal},
        },
        crypto::{Multihash, PublicKey, SecretKey},
        utils::trie::{Record, Trie},
    };
    use libp2p::{gossipsub::MessageId, PeerId};
    use std::collections::HashMap;

    type TestHasher = sha2::Sha256;

    const THRESHOLD: f64 = 0.5;
    const TEST_KEY: &[u8] = b"test_key";
    const TEST_VALUE: &[u8] = b"test_value";

    struct TestContext {
        dag: Tree<TestHasher>,
        arc_dag: Option<Arc<Tree<TestHasher>>>,
        genesis_hash: Multihash,
        public_key: PublicKey,
    }

    impl TestContext {
        fn new() -> Self {
            let secret_key = SecretKey::random();
            let public_key = secret_key.public_key();
            let genesis_block = Self::create_genesis_block(&public_key);
            let genesis_hash = genesis_block.hash::<TestHasher>();
            let dag = Tree::with_genesis(genesis_block.clone(), THRESHOLD);

            Self {
                dag,
                arc_dag: None,
                genesis_hash,
                public_key,
            }
        }

        pub fn new_arc() -> Self {
            let secret_key = SecretKey::random();
            let public_key = secret_key.public_key();
            let genesis_block = Self::create_genesis_block(&public_key);
            let genesis_hash = genesis_block.hash::<TestHasher>();
            let dag = Tree::with_genesis(genesis_block.clone(), THRESHOLD);
            let arc_dag = Tree::with_genesis(genesis_block.clone(), THRESHOLD);

            Self {
                dag,
                arc_dag: Some(Arc::new(arc_dag)),
                genesis_hash,
                public_key,
            }
        }

        fn create_genesis_block(pk: &PublicKey) -> Block {
            block::Builder::new()
                .with_parent_hash(Multihash::default())
                .with_height(0)
                .with_proposer_pk(pk.clone())
                .with_proposer_weight(0)
                .build()
        }

        fn create_test_proposal(
            &self,
            parent: Multihash,
            key: &[u8],
            value: &[u8],
        ) -> (Proposal, HashMap<Multihash, Vec<u8>>) {
            let record = Record::new(0, value.to_vec());
            let diff = Diff::new(None, record.clone());

            let proposal = proposal::Builder::new()
                .with_parent(parent)
                .with_diff(key.to_vec(), diff)
                .with_proposer_pk(self.public_key.clone())
                .with_proposer_weight(0)
                .build()
                .expect("Failed to create proposal");

            let trie = Trie::<TestHasher>::from_root(parent);
            let proofs = proposal.generate_proofs(&trie);

            (proposal, proofs)
        }

        fn create_test_block(
            &self,
            parent: Multihash,
            height: u64,
            proposals: Vec<Multihash>,
        ) -> (Block, HashMap<Multihash, Vec<u8>>) {
            let block = block::Builder::new()
                .with_parent_hash(parent)
                .with_height(height)
                .with_proposals(proposals)
                .with_proposer_pk(self.public_key.clone())
                .with_proposer_weight(0)
                .build();

            let blocks = self.dag.storage.blocks.read();
            let parent_node = blocks.get(&parent).unwrap().read();
            let parent_trie = parent_node.trie.as_ref().unwrap();

            println!("parent_trie root: {:?}", parent_trie.root_hash());

            let proofs = block.generate_proofs(parent_trie);

            (block, proofs)
        }

        fn create_missing_parent_proposal(&self) -> Proposal {
            proposal::Builder::new()
                .with_parent(Multihash::wrap(0, &[1; 32]).unwrap())
                .with_proposer_pk(self.public_key.clone())
                .with_proposer_weight(0)
                .with_code(0)
                .build()
                .expect("Failed to create missing parent proposal")
        }

        fn create_missing_parent_block(&self, height: u64) -> Block {
            block::Builder::new()
                .with_parent_hash(Multihash::wrap(0, &[1; 32]).unwrap())
                .with_height(height)
                .with_proposer_pk(self.public_key.clone())
                .with_proposer_weight(0)
                .build()
        }

        fn random_message_id() -> MessageId {
            MessageId::new(&rand::random::<[u8; 32]>())
        }

        fn random_peer_id() -> PeerId {
            PeerId::random()
        }
    }

    // DAG tests
    #[test]
    fn dag_empty_creation() {
        let dag = Tree::<TestHasher>::empty(THRESHOLD);
        assert_eq!(dag.threshold, THRESHOLD);
        assert!(dag.storage.genesis_hash.is_none());
    }

    #[test]
    fn dag_with_genesis() {
        let ctx = TestContext::new();
        assert_eq!(ctx.dag.threshold, THRESHOLD);
        assert_eq!(ctx.dag.storage.genesis_hash, Some(ctx.genesis_hash));
    }

    #[tokio::test]
    async fn update_proposal_success() {
        let ctx = TestContext::new();
        let (proposal, proofs) = ctx.create_test_proposal(ctx.genesis_hash, TEST_KEY, TEST_VALUE);
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let result = ctx
            .dag
            .update_proposal(proposal.clone(), proofs, msg_id.clone(), peer_id);

        assert!(result.validated_msgs.is_empty());
        assert!(result.invalidated_msgs.is_empty());

        let proposal_hash = proposal.hash::<TestHasher>();
        let result = ctx
            .dag
            .update_proposal_client_validation(proposal_hash, true);

        assert_eq!(result.validated_msgs.len(), 1);
        assert_eq!(result.validated_msgs[0].0, msg_id);
        assert_eq!(result.validated_msgs[0].1, peer_id);
    }

    #[tokio::test]
    async fn update_proposal_client_invalid() {
        let ctx = TestContext::new();
        let (proposal, proofs) = ctx.create_test_proposal(ctx.genesis_hash, TEST_KEY, TEST_VALUE);
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let _result = ctx
            .dag
            .update_proposal(proposal.clone(), proofs, msg_id.clone(), peer_id);

        let proposal_hash = proposal.hash::<TestHasher>();
        let result = ctx
            .dag
            .update_proposal_client_validation(proposal_hash, false);

        assert_eq!(result.invalidated_msgs.len(), 1);
        assert_eq!(result.invalidated_msgs[0].0, msg_id);
        assert_eq!(result.invalidated_msgs[0].1, peer_id);
    }

    #[tokio::test]
    async fn update_block_success() {
        let ctx = TestContext::new();

        // First create and validate a proposal
        let (proposal, prop_proofs) =
            ctx.create_test_proposal(ctx.genesis_hash, TEST_KEY, TEST_VALUE);
        let proposal_hash = proposal.hash::<TestHasher>();
        let prop_msg_id = TestContext::random_message_id();
        let prop_peer_id = TestContext::random_peer_id();

        ctx.dag
            .update_proposal(proposal, prop_proofs, prop_msg_id, prop_peer_id);
        ctx.dag
            .update_proposal_client_validation(proposal_hash, true);

        // Now create a block that includes the proposal
        let (block, block_proofs) = ctx.create_test_block(ctx.genesis_hash, 1, vec![proposal_hash]);
        let block_msg_id = TestContext::random_message_id();
        let block_peer_id = TestContext::random_peer_id();

        let result = ctx
            .dag
            .update_block(block, block_proofs, block_msg_id.clone(), block_peer_id);

        assert_eq!(result.validated_msgs.len(), 1);
        assert_eq!(result.validated_msgs[0].0, block_msg_id);
        assert_eq!(result.validated_msgs[0].1, block_peer_id);
    }

    #[tokio::test]
    async fn update_block_below_checkpoint() {
        let ctx = TestContext::new();

        // Create a block with height lower than checkpoint
        let low_block = block::Builder::new()
            .with_parent_hash(ctx.genesis_hash)
            .with_height(0) // Same as genesis, should be below checkpoint
            .with_proposer_pk(ctx.public_key)
            .with_proposer_weight(50)
            .build();

        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let result = ctx
            .dag
            .update_block(low_block, HashMap::new(), msg_id.clone(), peer_id);

        assert_eq!(result.invalidated_msgs.len(), 1);
        assert_eq!(result.invalidated_msgs[0].0, msg_id);
        assert_eq!(result.invalidated_msgs[0].1, peer_id);
    }

    #[test]
    fn block_node_invalidate_descendants() {
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let mut node = BlockNode::<TestHasher>::new_missing();
        node.metadata = Some(Metadata::new(msg_id.clone(), peer_id));
        node.state = State::Valid;

        let mut result = ProcessResult::new();
        node.invalidate_descendants(&mut result);

        assert_eq!(node.state, State::Invalid);
        assert_eq!(result.invalidated_msgs.len(), 1);
        assert_eq!(result.invalidated_msgs[0].0, msg_id);
        assert_eq!(result.invalidated_msgs[0].1, peer_id);
    }

    #[test]
    fn proposal_node_invalidate_descendants() {
        let parent_block = Arc::new(ParkingRwLock::new(BlockNode::<TestHasher>::new_missing()));
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let mut node = ProposalNode::new_missing(parent_block);
        node.metadata = Some(Metadata::new(msg_id.clone(), peer_id));
        node.state = State::Valid;

        let mut result = ProcessResult::new();
        node.invalidate_descendants(&mut result);

        assert_eq!(node.state, State::Invalid);
        assert_eq!(result.invalidated_msgs.len(), 1);
        assert_eq!(result.invalidated_msgs[0].0, msg_id);
        assert_eq!(result.invalidated_msgs[0].1, peer_id);
    }

    #[tokio::test]
    async fn concurrent_proposal_updates() {
        let ctx = TestContext::new_arc();
        let mut handles = vec![];

        let dag = ctx.arc_dag.as_ref().unwrap().clone();

        for i in 0..10 {
            let dag = dag.clone();
            let genesis_hash = ctx.genesis_hash;
            let public_key = ctx.public_key.clone();

            let handle = tokio::spawn(async move {
                let key = format!("key_{i}");
                let value = format!("value_{i}");
                let record = Record::new(0, value.as_bytes().to_vec());
                let diff = Diff::new(None, record);

                let proposal = proposal::Builder::new()
                    .with_parent(genesis_hash)
                    .with_diff(key.as_bytes().to_vec(), diff)
                    .with_proposer_pk(public_key)
                    .with_proposer_weight(50)
                    .build()
                    .expect("Failed to create proposal");

                let trie = Trie::<TestHasher>::from_root(genesis_hash);
                let proofs = proposal.generate_proofs(&trie);

                let msg_id = MessageId::new(format!("msg_{i}").as_bytes());
                let peer_id = PeerId::random();

                dag.update_proposal(proposal, proofs, msg_id, peer_id)
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        for result in results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn state_transitions() {
        // Test all state variants
        assert_eq!(State::Pending, State::Pending);
        assert_eq!(State::Valid, State::Valid);
        assert_eq!(State::Invalid, State::Invalid);

        assert_ne!(State::Pending, State::Valid);
        assert_ne!(State::Valid, State::Invalid);
        assert_ne!(State::Pending, State::Invalid);
    }

    #[test]
    fn checkpoint_creation_logic() {
        let ctx = TestContext::new();

        // Access the checkpoint height method through testing
        let checkpoint_height = ctx.dag.checkpoint_height();
        assert_eq!(checkpoint_height, 0); // Genesis height

        let block_height = ctx.dag.block_height(&ctx.genesis_hash);
        assert_eq!(block_height, Some(0));
    }

    #[test]
    fn update_tips_logic() {
        let ctx = TestContext::new();
        let new_weight = 200;
        let new_hash = Multihash::default();

        // Test the internal update_tips logic
        ctx.dag.update_tips(new_hash, new_weight);

        let tips = ctx.dag.storage.tips.read();
        assert!(tips.contains_key(&new_weight));
        assert_eq!(tips.get(&new_weight), Some(&new_hash));
    }

    #[test]
    fn proposal_validation_missing_parent() {
        let ctx = TestContext::new();
        let proposal = ctx.create_missing_parent_proposal();
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let result = ctx
            .dag
            .update_proposal(proposal, HashMap::new(), msg_id.clone(), peer_id);

        // Should not be validated due to missing/invalid parent
        assert!(result.validated_msgs.is_empty());
    }

    #[tokio::test]
    async fn block_validation_missing_parent() {
        let ctx = TestContext::new();
        let block = ctx.create_missing_parent_block(1);
        let msg_id = TestContext::random_message_id();
        let peer_id = TestContext::random_peer_id();

        let result = ctx.dag.update_block(block, HashMap::new(), msg_id, peer_id);

        assert!(result.validated_msgs.is_empty());
    }
}
