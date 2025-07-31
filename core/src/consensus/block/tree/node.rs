use std::sync::Arc;

use derivative::Derivative;

use crate::{
    consensus::{
        block::{
            self,
            tree::{dag::Node, Mode},
            Block,
        },
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    utils::Record,
};

mod block_node;
mod proposal_node;

pub use block_node::BlockNode;
pub use block_node::SerializedBlockNode;
pub use proposal_node::ProposalNode;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub enum UnifiedNode<H, T: Record> {
    Block(BlockNode<H, T>),
    Proposal(ProposalNode<T>),
}

impl<H: Hasher, T: Record> UnifiedNode<H, T> {
    pub fn new_block(block: Block<T>, witness: block::Witness, mode: Arc<Mode>) -> Self {
        UnifiedNode::Block(BlockNode::new(block, witness, mode))
    }

    pub fn new_proposal(proposal: Proposal<T>, witness: proposal::Witness) -> Self {
        UnifiedNode::Proposal(ProposalNode::new(proposal, witness))
    }

    pub fn as_block(&self) -> Option<&BlockNode<H, T>> {
        if let UnifiedNode::Block(node) = self {
            Some(node)
        } else {
            None
        }
    }

    pub fn as_proposal(&self) -> Option<&ProposalNode<T>> {
        if let UnifiedNode::Proposal(node) = self {
            Some(node)
        } else {
            None
        }
    }

    pub fn into_proposal(self) -> ProposalNode<T> {
        if let UnifiedNode::Proposal(node) = self {
            node
        } else {
            panic!("Cannot convert BlockNode to ProposalNode");
        }
    }
}

impl<H: Hasher, T: Record> Node for UnifiedNode<H, T> {
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
