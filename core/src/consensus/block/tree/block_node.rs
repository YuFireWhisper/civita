use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use derivative::Derivative;
use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        self,
        tree::{proposal_node::ProposalNode, Metadata, ProcessResult, State},
        Block,
    },
    crypto::{Hasher, Multihash, SecretKey},
    utils::trie::{Trie, Weight},
};

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct BlockNode<H> {
    pub state: State,

    pub block: Option<Block>,
    pub witness: Option<block::Witness>,

    pub proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,
    valided_proposals: HashSet<Multihash>,

    pub trie: Option<Trie<H>>,
    pub weight: Option<Weight>,
    pub cumulative_weight: Option<Weight>,

    pub parent: Option<Arc<ParkingRwLock<BlockNode<H>>>>,

    pub children_blocks: HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,
    pub children_proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,

    pub metadata: Option<Metadata>,

    pub is_genesis: bool,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Builder<H> {
    state: State,

    block: Option<Block>,
    witness: Option<block::Witness>,

    trie: Option<Trie<H>>,
    weight: Option<Weight>,
    cumulative_weight: Option<Weight>,

    parent: Option<Arc<ParkingRwLock<BlockNode<H>>>>,

    proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,
    valided_proposals: HashSet<Multihash>,

    metadata: Option<Metadata>,

    is_genesis: bool,
}

impl<H: Hasher> BlockNode<H> {
    pub fn new_missing() -> Self {
        Self::default()
    }

    pub fn new_genesis() -> Self {
        let mut genesis_trie = Trie::empty();
        let _ = genesis_trie.commit();

        Self {
            state: State::Valid,

            trie: Some(genesis_trie),
            weight: Some(0),
            cumulative_weight: Some(0),

            is_genesis: true,

            ..Default::default()
        }
    }

    pub fn generate_next(
        parent: Arc<ParkingRwLock<BlockNode<H>>>,
        sk: &SecretKey,
        vdf_proof: Vec<u8>,
    ) -> Self {
        let parent_read = parent.read();

        assert!(parent_read.state.is_valid());

        let parent_hash = parent_read.hash().expect("Parent block must be valid");
        let parent_height = parent_read.height().expect("Parent block must have height");
        let parent_trie = parent_read
            .trie
            .as_ref()
            .expect("Parent trie must be valid");

        let props = parent_read.collect_valid_children_proposals();

        let proposer_pk = sk.public_key();

        let proposer_weight = {
            let key = proposer_pk.to_hash::<H>().to_bytes();
            parent_trie.get(&key).map_or(0, |v| v.weight)
        };

        let block = block::Builder::new()
            .with_parent_hash(parent_hash)
            .with_height(parent_height.wrapping_add(1))
            .with_proposals(props.keys().cloned())
            .with_proposer_pk(proposer_pk)
            .with_proposer_weight(proposer_weight)
            .build();

        let (new_trie, new_weight) =
            Self::calc_new_trie_and_weight(props.values(), proposer_weight, parent_trie);

        let sig = sk.sign(&block.hash::<H>().to_bytes());
        let proofs = block.generate_proofs::<H>(parent_trie);
        let witness = block::Witness::new(sig, proofs, vdf_proof);

        Builder::new()
            .with_state(State::Valid)
            .with_block_data(block, witness)
            .with_trie(new_trie)
            .with_weight(new_weight)
            .with_cumulative_weight(parent_read.cumulative_weight.unwrap_or(0) + new_weight)
            .with_proposals(props)
            .build()
    }

    pub fn set_parent(&mut self, parent: Arc<ParkingRwLock<BlockNode<H>>>) {
        self.parent = Some(parent);
    }

    fn collect_valid_children_proposals(
        &self,
    ) -> BTreeMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>> {
        self.children_proposals
            .values()
            .filter(|node| node.read().state.is_valid())
            .map(|node| (node.read().hash().unwrap(), node.clone()))
            .collect()
    }

    pub fn set_block_data(&mut self, block: Block, witness: block::Witness) {
        self.block = Some(block);
        self.witness = Some(witness);
    }

    pub fn set_metadata(&mut self, msg_id: MessageId, source: PeerId) {
        self.metadata = Some(Metadata::new(msg_id, source));
    }

    pub fn on_proposal_validated(&mut self, hash: Multihash, result: &mut ProcessResult) {
        if !self.block_contains(&hash) || !self.proposals.contains_key(&hash) {
            return;
        }

        self.valided_proposals.insert(hash);

        if let Some(r) = self.try_validate(false) {
            result.merge(r);
        }
    }

    fn block_contains(&self, hash: &Multihash) -> bool {
        self.block
            .as_ref()
            .is_some_and(|b| b.proposals.contains(hash))
    }

    pub fn try_validate(&mut self, unchecked: bool) -> Option<ProcessResult> {
        if !unchecked && !self.can_convert_to_valid() {
            return None;
        }

        let parent = self.parent.as_ref()?;
        let parent_read = parent.read();
        let parent_trie = parent_read.trie.as_ref()?;
        let parent_cumulative_weight = parent_read.cumulative_weight?;

        debug_assert!(
            !parent_read.state.is_invalid(),
            "If parent is invalid, proposals will not be valid either"
        );

        let block = self.block.as_ref()?;
        let witness = self.witness.as_ref()?;

        if !unchecked && !block.verify_proposer_weight::<H>(witness, parent_trie.root_hash()) {
            drop(parent_read);
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let (new_trie, new_weight) = Self::calc_new_trie_and_weight(
            self.proposals.values(),
            block.proposer_weight,
            parent_trie,
        );

        drop(parent_read);

        self.state = State::Valid;
        self.trie = Some(new_trie);
        self.weight = Some(new_weight);
        self.cumulative_weight = Some(parent_cumulative_weight + new_weight);

        let mut result = ProcessResult::new();

        if let Some(metadata) = &self.metadata {
            result.add_validated(metadata.msg_id.clone(), metadata.source);
        }

        self.children_blocks.values().for_each(|child| {
            if let Some(r) = child.write().try_validate(false) {
                result.merge(r);
            }
        });

        self.children_proposals.values().for_each(|child| {
            child.read().children_blocks.values().for_each(|block| {
                if let Some(r) = block.write().try_validate(false) {
                    result.merge(r);
                }
            });
        });

        Some(result)
    }

    fn can_convert_to_valid(&self) -> bool {
        if self.state.is_valid() || self.state.is_invalid() {
            // Alrady established
            return false;
        }

        self.valided_proposals.len() == self.block.as_ref().map_or(0, |b| b.proposals.len())
            && self
                .parent
                .as_ref()
                .is_some_and(|p| p.read().state.is_valid())
            && self.block.is_some()
            && self.witness.is_some()
    }

    pub fn invalidate_descendants(&mut self, result: &mut ProcessResult) {
        self.state = State::Invalid;

        if let Some(metadata) = &self.metadata {
            result.add_invalidated(metadata.msg_id.clone(), metadata.source);
        }

        self.children_blocks.values().for_each(|child| {
            child.write().invalidate_descendants(result);
        });

        self.children_proposals.values().for_each(|child| {
            child.write().invalidate_descendants(result);
        });

        self.proposals.clear();
    }

    fn calc_new_trie_and_weight<'a, I>(
        proposals: I,
        base_weight: Weight,
        parent_trie: &Trie<H>,
    ) -> (Trie<H>, Weight)
    where
        I: IntoIterator<Item = &'a Arc<ParkingRwLock<ProposalNode<H>>>>,
    {
        let mut trie = parent_trie.clone();
        let mut weight = base_weight;

        proposals.into_iter().for_each(|node| {
            let node_read = node.read();
            let proposal = node_read.proposal.as_ref().unwrap();
            let witness = node_read.witness.as_ref().unwrap();
            let p_weight = node_read.proposer_weight.unwrap();

            proposal.apply_operations(&mut trie, witness);
            weight += p_weight;
        });

        (trie, weight)
    }

    pub fn hash(&self) -> Option<Multihash> {
        if self.is_genesis {
            return Some(Multihash::default());
        }

        self.block.as_ref().map(|b| b.hash::<H>())
    }

    pub fn height(&self) -> Option<u64> {
        if self.is_genesis {
            return Some(0);
        }

        self.block.as_ref().map(|b| b.height)
    }

    pub fn trie_root_hash(&self) -> Option<Multihash> {
        self.trie.as_ref().map(|t| t.root_hash())
    }

    pub fn is_missing(&self) -> bool {
        self.block.is_none() && self.witness.is_none()
    }
}

impl<H: Hasher> Builder<H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_state(mut self, state: State) -> Self {
        self.state = state;
        self
    }

    pub fn with_block_data(mut self, block: Block, witness: block::Witness) -> Self {
        self.block = Some(block);
        self.witness = Some(witness);
        self
    }

    pub fn with_trie(mut self, trie: Trie<H>) -> Self {
        self.trie = Some(trie);
        self
    }

    pub fn with_weight(mut self, weight: Weight) -> Self {
        self.weight = Some(weight);
        self
    }

    pub fn with_cumulative_weight(mut self, cumulative_weight: Weight) -> Self {
        self.cumulative_weight = Some(cumulative_weight);
        self
    }

    pub fn with_proposals<I>(mut self, proposals: I) -> Self
    where
        I: IntoIterator<Item = (Multihash, Arc<ParkingRwLock<ProposalNode<H>>>)>,
    {
        proposals.into_iter().for_each(|(hash, proposal)| {
            if proposal.read().state.is_valid() {
                self.valided_proposals.insert(hash);
            }
            self.proposals.insert(hash, proposal);
        });
        self
    }

    pub fn build(self) -> BlockNode<H> {
        BlockNode {
            state: self.state,

            block: self.block,
            witness: self.witness,

            trie: self.trie,
            weight: self.weight,
            cumulative_weight: self.cumulative_weight,

            parent: self.parent,

            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),

            proposals: self.proposals,
            valided_proposals: self.valided_proposals,

            metadata: self.metadata,

            is_genesis: self.is_genesis,
        }
    }
}
