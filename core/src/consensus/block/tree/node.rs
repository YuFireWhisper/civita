use std::sync::{atomic::AtomicU64, Arc};

use derivative::Derivative;
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::{
            self,
            tree::{dag::Node, Mode, State},
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
};

mod block_node;
mod proposal_node;

pub use block_node::BlockNode;
pub use proposal_node::ProposalNode;

type AtomicWeight = AtomicU64;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub enum UnifiedNode<H> {
    Block(BlockNode<H>),
    Proposal(ProposalNode),
}

impl<H: Hasher> UnifiedNode<H> {
    pub fn new_block(
        block: Block,
        witness: Option<block::Witness>,
        state: Arc<ParkingRwLock<State>>,
        mode: Arc<Mode>,
    ) -> Self {
        UnifiedNode::Block(BlockNode::new(block, witness, state, mode))
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

    pub fn as_proposal(&self) -> Option<&ProposalNode> {
        if let UnifiedNode::Proposal(node) = self {
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
