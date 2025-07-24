use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::{
        block::tree::{block_node::BlockNode, Metadata, ProcessResult, State},
        proposal::{self, Proposal},
    },
    crypto::{Hasher, Multihash},
    utils::trie::Weight,
};

pub struct ProposalNode<H> {
    pub state: State,

    pub proposal: Option<Proposal>,
    pub witness: Option<proposal::Witness>,

    pub client_validated: Option<bool>,

    pub proposer_weight: Option<Weight>,

    pub parent_block: Arc<ParkingRwLock<BlockNode<H>>>,
    pub parent_proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,
    validated_parent_proposals: HashSet<Multihash>,

    pub children_blocks: HashMap<Multihash, Arc<ParkingRwLock<BlockNode<H>>>>,
    pub children_proposals: HashMap<Multihash, Arc<ParkingRwLock<ProposalNode<H>>>>,

    pub metadata: Option<Metadata>,
}

impl<H: Hasher> ProposalNode<H> {
    pub fn new_missing() -> Self {
        Self {
            state: State::Pending,

            proposal: None,
            witness: None,

            client_validated: None,

            proposer_weight: None,

            parent_block: Arc::new(ParkingRwLock::new(BlockNode::new_missing())),
            parent_proposals: HashMap::new(),
            validated_parent_proposals: HashSet::new(),

            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),

            metadata: None,
        }
    }

    pub fn new_valid_uncheck(
        proposal: Proposal,
        witenss: proposal::Witness,
        weight: Weight,
    ) -> Self {
        Self {
            state: State::Valid,

            proposal: Some(proposal),
            witness: Some(witenss),

            client_validated: None,

            proposer_weight: Some(weight),

            parent_block: Arc::new(ParkingRwLock::new(BlockNode::new_missing())),
            parent_proposals: HashMap::new(),
            validated_parent_proposals: HashSet::new(),

            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),

            metadata: None,
        }
    }

    pub fn on_parent_proposal_validated(&mut self, hash: Multihash, result: &mut ProcessResult) {
        if !self.parent_proposal_contains(&hash) {
            return;
        }

        self.validated_parent_proposals.insert(hash);

        if let Some(r) = self.try_validate() {
            result.merge(r);
        }
    }

    fn parent_proposal_contains(&self, hash: &Multihash) -> bool {
        self.parent_proposals.contains_key(hash)
            || self
                .proposal
                .as_ref()
                .is_some_and(|p| p.dependencies.contains(hash))
    }

    pub fn try_validate(&mut self) -> Option<ProcessResult> {
        if !self.can_convert_to_valid() {
            return None;
        }

        let parent_trie_root = self.parent_block.read().trie_root_hash().unwrap();
        let proposal = self.proposal.as_ref().unwrap();
        let witness = self.witness.as_ref().unwrap();

        if !proposal.verify_operations::<H>(witness, parent_trie_root) {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let Some(proposer_weight) = proposal.verify_proposer_weight::<H>(witness, parent_trie_root)
        else {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        };

        self.state = State::Valid;
        self.proposer_weight = Some(proposer_weight);

        let mut result = ProcessResult::new();

        if let Some(metadata) = &self.metadata {
            result.add_validated(metadata.msg_id.clone(), metadata.source);
        }

        let hash = self.hash().unwrap();
        self.children_blocks.values().for_each(|child| {
            child.write().on_proposal_validated(hash, &mut result);
        });

        Some(result)
    }

    fn can_convert_to_valid(&self) -> bool {
        self.state.is_pending()
            && self
                .proposal
                .as_ref()
                .is_some_and(|p| p.dependencies.len() == self.validated_parent_proposals.len())
            && self.witness.is_some()
            && self.client_validated.is_some()
            && self.parent_block.read().state.is_valid()
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
}
