use dashmap::DashSet;
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
    pub remaining: DashSet<Vec<u8>>,
    pub existing_keys: DashSet<Vec<u8>>,
}

impl<T: Record> ProposalNode<T> {
    pub fn new(proposal: Proposal<T>, witness: proposal::Witness) -> Self {
        Self {
            remaining: DashSet::from_iter(proposal.operations.keys().cloned()),
            proposal,
            witness,
            proposer_weight: Default::default(),
            existing_keys: DashSet::new(),
        }
    }

    pub fn id<H: Hasher>(&self) -> Multihash {
        self.proposal.hash::<H>()
    }

    pub fn parents(&self) -> Vec<Multihash> {
        self.proposal
            .dependencies
            .iter()
            .chain(std::iter::once(&self.proposal.parent))
            .copied()
            .collect()
    }

    pub fn on_block_parent_valid<H: Hasher>(&self, parent: &BlockNode<H, T>) -> bool {
        let trie_root = {
            let mut trie = parent.trie.write();

            let key = self.proposal.proposer_pk.to_hash::<H>().to_bytes();
            let iter = self
                .proposal
                .operations
                .keys()
                .map(|k| k.as_slice())
                .chain(std::iter::once(key.as_slice()));

            if !trie.expand(iter, &self.witness.proofs) {
                return false;
            }

            trie.root_hash()
        };

        let Some(weight) = self
            .proposal
            .verify_proposer_weight::<H>(&self.witness, trie_root)
        else {
            return false;
        };

        *self.proposer_weight.write() = weight;

        true
    }

    pub fn on_proposal_parent_valid(&self, parent: &ProposalNode<T>) -> bool {
        let mut intersection = Vec::new();

        let is_valid = parent.proposal.operations.keys().all(|key| {
            if self.existing_keys.contains(key) {
                return false;
            }

            if self.remaining.contains(key) {
                intersection.push(key.clone());
                return true;
            }

            true
        });

        if !is_valid || !intersection.is_empty() {
            return false;
        }

        intersection.iter().for_each(|key| {
            self.remaining.remove(key);
        });

        parent.proposal.operations.keys().cloned().for_each(|key| {
            self.existing_keys.insert(key);
        });

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
            remaining: self.remaining.clone(),
            existing_keys: self.existing_keys.clone(),
        }
    }
}
