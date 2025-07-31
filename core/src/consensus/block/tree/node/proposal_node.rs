use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::tree::node::BlockNode,
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    utils::Record,
};

pub struct ProposalNode<T: Record> {
    pub proposal: Proposal<T>,
    pub witness: proposal::Witness,
    pub proposer_weight: ParkingRwLock<T::Weight>,
}

impl<T: Record> ProposalNode<T> {
    pub fn new(proposal: Proposal<T>, witness: proposal::Witness) -> Self {
        Self {
            proposal,
            witness,
            proposer_weight: Default::default(),
        }
    }

    pub fn id<H: Hasher>(&self) -> Multihash {
        self.proposal.hash::<H>()
    }

    pub fn on_block_parent_valid<H: Hasher>(&self, parent: &BlockNode<H, T>) -> bool {
        let trie_root = parent.trie_root_hash();

        let Some(weight) = self
            .proposal
            .verify_proposer_weight::<H>(&self.witness, trie_root)
        else {
            return false;
        };

        *self.proposer_weight.write() = weight;

        true
    }

    pub fn on_proposal_parent_valid(&self, _: &ProposalNode<T>) -> bool {
        true
    }

    pub fn validate(&self) -> bool {
        true
    }
}

impl<T: Record> Clone for ProposalNode<T> {
    fn clone(&self) -> Self {
        Self {
            proposal: self.proposal.clone(),
            witness: self.witness.clone(),
            proposer_weight: ParkingRwLock::new(*self.proposer_weight.read()),
        }
    }
}
