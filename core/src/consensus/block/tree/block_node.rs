use std::{
    collections::{BTreeMap, HashMap},
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
    crypto::{Hasher, Multihash, PublicKey},
    utils::trie::{Trie, Weight},
};

pub struct BlockNode<H> {
    pub block: Option<Block>,
    pub state: State,

    pub trie: Option<Trie<H>>,
    pub weight: Weight,
    pub proofs: HashMap<Multihash, Vec<u8>>,

    pub parent: Option<Arc<ParkingRwLock<BlockNode<H>>>>,
    pub children_blocks: HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,
    pub children_proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,
    pub cumulative_weight: Weight,

    pub proposals: HashMap<Multihash, Option<Arc<ParkingRwLock<ProposalNode<H>>>>>,

    pub metadata: Option<Metadata>,
    pub is_genesis: bool,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Builder<H> {
    block: Option<Block>,
    state: State,

    trie: Option<Trie<H>>,
    weight: Weight,
    proofs: HashMap<Multihash, Vec<u8>>,

    parent: Option<Arc<ParkingRwLock<BlockNode<H>>>>,

    proposals: HashMap<Multihash, Option<Arc<ParkingRwLock<ProposalNode<H>>>>>,

    metadata: Option<Metadata>,
    is_genesis: bool,
}

impl<H: Hasher> BlockNode<H> {
    pub fn new_missing() -> Self {
        Self {
            block: None,
            state: State::Pending,

            trie: None,
            weight: Weight::default(),
            proofs: HashMap::new(),

            parent: None,
            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),
            proposals: HashMap::new(),
            cumulative_weight: Weight::default(),

            metadata: None,
            is_genesis: false,
        }
    }

    pub fn new_genesis(genesis_block: Block) -> Self {
        let mut genesis_trie = Trie::empty();
        let _ = genesis_trie.commit();

        Self {
            block: Some(genesis_block.clone()),
            state: State::Valid,

            trie: Some(genesis_trie),
            weight: Weight::default(),
            proofs: HashMap::new(),

            parent: None,
            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),
            proposals: HashMap::new(),
            cumulative_weight: genesis_block.proposer_weight,

            metadata: None,
            is_genesis: true,
        }
    }

    pub fn set_parent(&mut self, parent: Arc<ParkingRwLock<BlockNode<H>>>) -> bool {
        if self.parent.is_some() {
            return false;
        }
        self.cumulative_weight = parent.read().cumulative_weight;
        self.parent = Some(parent);
        true
    }

    pub fn generate(
        parent: Arc<ParkingRwLock<BlockNode<H>>>,
        proposer_pk: PublicKey,
    ) -> Option<(Self, HashMap<Multihash, Vec<u8>>)> {
        let parent_read = parent.read();
        let parent_block = parent_read.block.as_ref()?;
        let parent_trie = parent_read.trie.as_ref()?;

        let props = parent_read.collect_valid_children_proposals();
        let (proposer_weight, proofs) = {
            let key = proposer_pk.to_hash::<H>().to_bytes();
            let mut proofs = HashMap::new();
            parent_trie.prove(&key, &mut proofs);
            (parent_trie.get(&key).map_or(0, |v| v.weight), proofs)
        };

        let block = block::Builder::new()
            .with_parent_block::<H>(parent_block)
            .with_proposals(props.keys().cloned())
            .with_proposer_pk(proposer_pk)
            .with_proposer_weight(proposer_weight)
            .build();

        let (new_trie, new_weight) =
            Self::calc_new_trie_and_weight(props.values(), proposer_weight, parent_trie);

        drop(parent_read);

        let node = Builder::new()
            .with_block(block)
            .with_state(State::Valid)
            .with_trie(new_trie)
            .with_weight(new_weight)
            .with_parent(parent)
            .with_proposals(props)
            .build();

        Some((node, proofs))
    }

    pub fn collect_valid_children_proposals(
        &self,
    ) -> BTreeMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>> {
        self.children_proposals
            .values()
            .filter(|node| node.read().state == State::Valid)
            .map(|node| (node.read().hash().unwrap(), node.clone()))
            .collect()
    }

    pub fn set_block_data(
        &mut self,
        block: Block,
        proofs: HashMap<Multihash, Vec<u8>>,
        msg_id: MessageId,
        source: PeerId,
    ) {
        self.block = Some(block);
        self.proofs = proofs;
        self.metadata = Some(Metadata::new(msg_id, source));
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
    }

    pub fn try_validate(&mut self) -> Option<ProcessResult> {
        if self.is_genesis {
            return None;
        }

        match self.state {
            State::Valid | State::Invalid => return None,
            State::Pending => {}
        }

        if !self.check_proposals_state()? {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let parent = self.parent.as_ref()?;
        let parent_read = parent.read();
        let parent_trie = parent_read.trie.as_ref()?;

        debug_assert!(
            !parent_read.state.is_invalid(),
            "If parent is invalid, proposals will not be valid either"
        );

        let block = self.block.as_ref()?;

        if !block.verify_proposer_weight_with_proofs::<H>(&self.proofs, parent_trie.root_hash()) {
            drop(parent_read);
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let (new_trie, new_weight) = Self::calc_new_trie_and_weight(
            self.proposals.values().flatten(),
            block.proposer_weight,
            parent_trie,
        );

        drop(parent_read);

        self.state = State::Valid;
        self.trie = Some(new_trie);
        self.weight = new_weight;

        let mut result = ProcessResult::new();

        if let Some(metadata) = &self.metadata {
            result.add_validated(metadata.msg_id.clone(), metadata.source);
        }

        self.children_blocks.values().for_each(|child| {
            if let Some(r) = child.write().try_validate() {
                result.merge(r);
            }
        });

        self.children_proposals.values().for_each(|child| {
            child.read().child_blocks.values().for_each(|block| {
                if let Some(r) = block.write().try_validate() {
                    result.merge(r);
                }
            });
        });

        Some(result)
    }

    fn check_proposals_state(&self) -> Option<bool> {
        self.proposals
            .values()
            .try_fold(false, |is_pending, prop| {
                match prop.as_ref()?.read().state {
                    State::Invalid => None,
                    State::Pending => Some(true),
                    State::Valid => Some(is_pending),
                }
            })
            .map(|has_pending| !has_pending)
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
            let iter = node_read
                .proposal
                .as_ref()
                .unwrap()
                .diffs
                .iter()
                .map(|(k, v)| (k.as_slice(), v.to.clone()));
            trie.update_many(iter, Some(&node_read.proofs));
            weight += node_read.proposal.as_ref().unwrap().proposer_weight;
        });

        (trie, weight)
    }

    pub fn hash(&self) -> Option<Multihash> {
        self.block.as_ref().map(|b| b.hash::<H>())
    }

    pub fn height(&self) -> Option<u64> {
        self.block.as_ref().map(|b| b.height)
    }
}

impl<H: Hasher> Builder<H> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_block(mut self, block: Block) -> Self {
        self.block = Some(block);
        self
    }

    pub fn with_state(mut self, state: State) -> Self {
        self.state = state;
        self
    }

    pub fn with_trie(mut self, trie: Trie<H>) -> Self {
        self.trie = Some(trie);
        self
    }

    pub fn with_weight(mut self, weight: Weight) -> Self {
        self.weight = weight;
        self
    }

    pub fn with_parent(mut self, parent: Arc<ParkingRwLock<BlockNode<H>>>) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn with_proposals<I, T>(mut self, proposals: I) -> Self
    where
        I: IntoIterator<Item = (Multihash, T)>,
        T: Into<Option<Arc<ParkingRwLock<ProposalNode<H>>>>>,
    {
        self.proposals
            .extend(proposals.into_iter().map(|(k, v)| (k, v.into())));
        self
    }

    pub fn build(self) -> BlockNode<H> {
        let cumulative_weight = self
            .parent
            .as_ref()
            .map(|p| p.read().cumulative_weight)
            .unwrap_or(self.weight);

        BlockNode {
            block: self.block,
            state: self.state,
            trie: self.trie,
            weight: self.weight,
            proofs: self.proofs,
            parent: self.parent,
            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),
            proposals: HashMap::new(),
            cumulative_weight,
            metadata: self.metadata,
            is_genesis: self.is_genesis,
        }
    }
}
