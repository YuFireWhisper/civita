use std::{collections::HashMap, sync::Arc};

use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::tree::{block_node::BlockNode, Metadata, ProcessResult, State},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
};

pub struct ProposalNode<H> {
    pub state: State,

    pub proposal: Option<Proposal>,
    pub witness: Option<proposal::Witness>,

    pub client_validated: Option<bool>,

    pub parent_block: Arc<ParkingRwLock<BlockNode<H>>>,
    pub child_blocks: HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,

    pub metadata: Option<Metadata>,
}

impl<H: Hasher> ProposalNode<H> {
    pub fn new_missing() -> Self {
        Self {
            state: State::Pending,

            proposal: None,
            witness: None,

            client_validated: None,

            parent_block: Arc::new(ParkingRwLock::new(BlockNode::new_missing())),
            child_blocks: HashMap::new(),

            metadata: None,
        }
    }

    pub fn new_valid_uncheck(proposal: Proposal, witenss: proposal::Witness) -> Self {
        Self {
            state: State::Valid,

            proposal: Some(proposal),
            witness: Some(witenss),

            client_validated: None,

            parent_block: Arc::new(ParkingRwLock::new(BlockNode::new_missing())),
            child_blocks: HashMap::new(),

            metadata: None,
        }
    }

    pub fn try_validate(&mut self) -> Option<ProcessResult> {
        if !self.can_convert_to_valid() {
            return None;
        }

        let parent_trie_root = self.parent_block.read().trie_root_hash().unwrap();
        let proposal = self.proposal.as_ref().unwrap();
        let witness = self.witness.as_ref().unwrap();

        if !proposal.verify_proposer_weight::<H>(witness, parent_trie_root)
            || !proposal.verify_diffs::<H>(witness, parent_trie_root)
        {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        self.state = State::Valid;

        let mut result = ProcessResult::new();

        if let Some(metadata) = &self.metadata {
            result.add_validated(metadata.msg_id.clone(), metadata.source);
        }

        let hash = self.hash().unwrap();
        self.child_blocks.values().for_each(|child| {
            child.write().on_proposal_validated(hash, &mut result);
        });

        Some(result)
    }

    fn can_convert_to_valid(&self) -> bool {
        self.state.is_pending()
            && self.proposal.is_some()
            && self.witness.is_some()
            && self.client_validated.is_some()
            && self.parent_block.read().state.is_valid()
    }

    pub fn invalidate_descendants(&mut self, result: &mut ProcessResult) {
        self.state = State::Invalid;

        if let Some(metadata) = &self.metadata {
            result.add_invalidated(metadata.msg_id.clone(), metadata.source);
        }

        self.child_blocks.values().for_each(|child| {
            child.write().invalidate_descendants(result);
        });
    }

    pub fn set_proposal_data(&mut self, proposal: Proposal, witness: proposal::Witness) {
        self.proposal = Some(proposal);
        self.witness = Some(witness);
    }

    pub fn set_metadata(&mut self, msg_id: MessageId, source: PeerId) {
        self.metadata = Some(Metadata::new(msg_id, source));
    }

    pub fn set_client_validation(&mut self, is_valid: bool) -> Option<ProcessResult> {
        self.client_validated = Some(is_valid);

        if !is_valid {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            Some(result)
        } else {
            self.try_validate()
        }
    }

    pub fn hash(&self) -> Option<Multihash> {
        self.proposal.as_ref().map(|p| p.hash::<H>())
    }

    pub fn proofs(&self) -> Option<&HashMap<Multihash, Vec<u8>>> {
        self.witness.as_ref().map(|witness| &witness.proofs)
    }
}
