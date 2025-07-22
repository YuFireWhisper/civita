use std::{collections::HashMap, sync::Arc};

use libp2p::{gossipsub::MessageId, PeerId};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        tree::{proposal_node::ProposalNode, Metadata, ProcessResult, State},
        Block,
    },
    crypto::{Hasher, Multihash},
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

    pub proposals: HashMap<Multihash, Option<Arc<ParkingRwLock<ProposalNode<H>>>>>,

    pub metadata: Option<Metadata>,
    pub is_genesis: bool,
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
            weight: genesis_block.proposer_weight,
            proofs: HashMap::new(),
            parent: None,
            children_blocks: HashMap::new(),
            children_proposals: HashMap::new(),
            proposals: HashMap::new(),
            metadata: None,
            is_genesis: true,
        }
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

        let block = self.block.as_ref()?;

        let mut is_invalid = false;
        for prop in self.proposals.values().flatten() {
            match prop.read().state {
                State::Invalid => {
                    is_invalid = true;
                    break;
                }
                State::Pending => return None,
                State::Valid => {}
            }
        }

        if is_invalid {
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let parent_trie_root = {
            let parent = self.parent.as_ref()?;
            let parent_read = parent.read();

            debug_assert!(
                parent_read.state != State::Invalid,
                "If parent is invalid, proposals will not be valid either"
            );

            parent_read.trie.as_ref()?.root_hash()
        };

        if !block.verify_proposer_weight_with_proofs::<H>(&self.proofs, parent_trie_root) {
            println!("Block proposer weight verification failed",);
            let mut result = ProcessResult::new();
            self.invalidate_descendants(&mut result);
            return Some(result);
        }

        let mut trie = Trie::from_root(parent_trie_root);
        let mut weight = block.proposer_weight;

        self.proposals.values().flatten().for_each(|node| {
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

        let _ = trie.commit();

        self.state = State::Valid;
        self.trie = Some(trie);
        self.weight = weight;

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
}
