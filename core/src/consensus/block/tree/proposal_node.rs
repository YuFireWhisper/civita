use std::{collections::HashMap, sync::Arc};

use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::tree::{block_node::BlockNode, Metadata, ProcessResult, State},
        proposal::Proposal,
    },
    crypto::{Hasher, Multihash},
};

pub struct ProposalNode<H> {
    pub proposal: Option<Proposal>,
    pub state: State,
    pub proofs: HashMap<Multihash, Vec<u8>>,
    pub client_validated: Option<bool>,
    pub parent_block: Arc<ParkingRwLock<BlockNode<H>>>,
    pub child_blocks: HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,
    pub metadata: Option<Metadata>,
}

impl<H: Hasher> ProposalNode<H> {
    pub fn new_missing(parent_block: Arc<ParkingRwLock<BlockNode<H>>>) -> Self {
        Self {
            proposal: None,
            proofs: HashMap::new(),
            state: State::Pending,
            parent_block,
            child_blocks: HashMap::new(),
            client_validated: None,
            metadata: None,
        }
    }

    pub fn try_validate(&mut self) -> Option<ProcessResult> {
        match self.state {
            State::Valid | State::Invalid => {
                return None;
            }
            _ => {}
        }

        let parent_trie_root = self.parent_block.read().trie.as_ref()?.root_hash();
        let proposal = self.proposal.as_ref()?;

        if !proposal.verify_proposer_weight_with_proofs::<H>(&self.proofs, parent_trie_root)
            || !proposal.verify_diffs_with_proofs(&self.proofs, parent_trie_root)
        {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        self.client_validated?;

        self.state = State::Valid;

        let mut result = ProcessResult::new();

        if let Some(metadata) = &self.metadata {
            result.add_validated(metadata.msg_id.clone(), metadata.source);
        }

        self.child_blocks.values().for_each(|child| {
            if let Some(r) = child.write().try_validate() {
                result.merge(r);
            }
        });

        Some(result)
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

    pub fn set_proposal_data(
        &mut self,
        proposal: Proposal,
        proofs: HashMap<Multihash, Vec<u8>>,
        msg_id: MessageId,
        source: PeerId,
    ) {
        self.proposal = Some(proposal);
        self.proofs = proofs;
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
}
