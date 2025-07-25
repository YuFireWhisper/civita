use std::sync::{atomic::AtomicU64, Arc};

use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{self, tree::dag::Node, Block},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    utils::trie::Weight,
};

mod block_node;
mod proposal_node;

pub use block_node::BlockNode;
pub use proposal_node::ProposalNode;

type AtomicWeight = AtomicU64;

pub enum UnifiedNode<H> {
    Block(BlockNode<H>),
    Proposal(ProposalNode),
}

impl<H: Hasher> UnifiedNode<H> {
    pub fn new_block(
        block: Block,
        witness: block::Witness,
        tip: Arc<ParkingRwLock<(Weight, u64, Multihash)>>,
        checkpoint: Arc<ParkingRwLock<(Weight, Multihash)>>,
    ) -> Self {
        UnifiedNode::Block(BlockNode::new(block, witness, tip, checkpoint))
    }

    pub fn new_proposal(proposal: Proposal, witness: proposal::Witness) -> Self {
        UnifiedNode::Proposal(ProposalNode::new(proposal, witness))
    }

    pub fn as_block(&self) -> Option<&BlockNode<H>> {
        if let UnifiedNode::Block(node) = self {
            Some(node)
        } else {
            None
        }
    }
}

impl<H: Hasher> Node for UnifiedNode<H> {
    type Id = Multihash;

    fn id(&self) -> Self::Id {
        match self {
            UnifiedNode::Block(node) => node.id(),
            UnifiedNode::Proposal(node) => node.id::<H>(),
        }
    }

    fn validate(&self) -> bool {
        match self {
            UnifiedNode::Block(node) => node.validate(),
            UnifiedNode::Proposal(node) => node.validate(),
        }
    }

    fn on_parent_valid(&self, child: &Self) -> bool {
        match (self, child) {
            (UnifiedNode::Block(s), UnifiedNode::Block(c)) => s.on_block_parent_valid(c),
            (UnifiedNode::Block(s), UnifiedNode::Proposal(c)) => s.on_proposal_parent_valid(c),
            (UnifiedNode::Proposal(s), UnifiedNode::Block(c)) => s.on_block_parent_valid(c),
            (UnifiedNode::Proposal(s), UnifiedNode::Proposal(c)) => s.on_proposal_parent_valid(c),
        }
    }
}
