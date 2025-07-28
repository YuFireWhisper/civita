use std::sync::{atomic::Ordering, Arc};

use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        self,
        tree::{
            node::{AtomicWeight, ProposalNode},
            Mode, State,
        },
        Block,
    },
    crypto::{Hasher, Multihash},
    utils::trie::Trie,
};

pub struct BlockNode<H> {
    pub block: Block,
    pub witness: Option<block::Witness>,
    pub trie: ParkingRwLock<Trie<H>>,
    pub weight: AtomicWeight,
    pub cumulative_weight: AtomicWeight,
    pub state: Arc<ParkingRwLock<State>>,
    pub mode: Arc<Mode>,
}

impl<H: Hasher> BlockNode<H> {
    pub fn new(
        block: Block,
        witness: Option<block::Witness>,
        state: Arc<ParkingRwLock<State>>,
        mode: Arc<Mode>,
    ) -> Self {
        let trie = Trie::empty();
        let weight = AtomicWeight::default();
        let cumulative_weight = AtomicWeight::default();

        Self {
            block,
            witness,
            trie: ParkingRwLock::new(trie),
            weight,
            cumulative_weight,
            state,
            mode,
        }
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn on_block_parent_valid(&self, parent: &BlockNode<H>) -> bool {
        let Some(witness) = &self.witness else {
            return false;
        };

        let parent_trie = parent.trie.read();
        let root_hash = parent_trie.root_hash();

        if !self.block.verify_proposer_weight::<H>(witness, root_hash) {
            return false;
        }

        let cumulative_weight =
            parent.cumulative_weight.load(Ordering::Relaxed) + self.block.proposer_weight;

        *self.trie.write() = parent_trie.clone();
        self.weight
            .store(self.block.proposer_weight, Ordering::Relaxed);
        self.cumulative_weight
            .store(cumulative_weight, Ordering::Relaxed);

        true
    }

    pub fn on_proposal_parent_valid(&self, parent: &ProposalNode) -> bool {
        let mut trie = self.trie.write();

        let prop = &parent.proposal;
        let witness = &parent.witness;
        let weight = parent.proposer_weight.load(Ordering::Relaxed);

        prop.apply_operations(&mut trie, witness);
        self.weight.fetch_add(weight, Ordering::Relaxed);
        self.cumulative_weight.fetch_add(weight, Ordering::Relaxed);

        true
    }

    pub fn validate(&self) -> bool {
        if let Mode::Normal(keys) = self.mode.as_ref() {
            self.trie.write().retain(keys.iter().map(|k| k.as_slice()));
        }

        let cumulative_weight = self.cumulative_weight.load(Ordering::Relaxed);
        let weight = self.weight.load(Ordering::Relaxed);
        let total_weight = self.trie.read().weight();
        let height = self.block.height;
        let id = self.id();

        {
            let mut state = self.state.write();
            state.update_tip(cumulative_weight, height, id);
            state.update_checkpoint(weight, total_weight, id);
        }

        true
    }

    pub fn height(&self) -> u64 {
        self.block.height
    }

    pub fn trie_root_hash(&self) -> Multihash {
        self.trie.read().root_hash()
    }
}

impl<H> Clone for BlockNode<H> {
    fn clone(&self) -> Self {
        Self {
            block: self.block.clone(),
            witness: self.witness.clone(),
            trie: ParkingRwLock::new(self.trie.read().clone()),
            weight: AtomicWeight::new(self.weight.load(Ordering::Relaxed)),
            cumulative_weight: AtomicWeight::new(self.cumulative_weight.load(Ordering::Relaxed)),
            state: Arc::clone(&self.state),
            mode: self.mode.clone(),
        }
    }
}
