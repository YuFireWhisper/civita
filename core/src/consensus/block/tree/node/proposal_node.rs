use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    consensus::{
        block::tree::node::BlockNode,
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
};

pub struct ProposalNode {
    pub proposal: Proposal,
    pub witness: proposal::Witness,
    pub proposer_weight: AtomicU64,
}

impl ProposalNode {
    pub fn new(proposal: Proposal, witness: proposal::Witness) -> Self {
        Self {
            proposal,
            witness,
            proposer_weight: AtomicU64::new(0),
        }
    }

    pub fn id<H: Hasher>(&self) -> Multihash {
        self.proposal.hash::<H>()
    }

    pub fn on_block_parent_valid<H: Hasher>(&self, parent: &BlockNode<H>) -> bool {
        let trie_root = parent.trie_root_hash();

        if !self
            .proposal
            .verify_operations::<H>(&self.witness, trie_root)
        {
            return false;
        }

        let Some(weight) = self
            .proposal
            .verify_proposer_weight::<H>(&self.witness, trie_root)
        else {
            return false;
        };

        self.proposer_weight.store(weight, Ordering::Relaxed);

        true
    }

    pub fn on_proposal_parent_valid(&self, parent: &ProposalNode) -> bool {
        let parent_op = &parent.proposal.operations;

        self.proposal.operations.iter().any(|(k, op)| {
            parent_op
                .get(k)
                .is_some_and(|pop| op.from.as_ref().is_none_or(|from| from != &pop.to))
        })
    }

    pub fn validate(&self) -> bool {
        true
    }
}
