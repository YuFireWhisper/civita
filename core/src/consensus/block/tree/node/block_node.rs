use std::sync::{atomic::Ordering, Arc};

use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        self,
        tree::node::{AtomicWeight, ProposalNode},
        Block,
    },
    crypto::{Hasher, Multihash},
    utils::trie::{Trie, Weight},
};

pub struct BlockNode<H> {
    pub block: Block,
    pub witness: block::Witness,
    pub trie: ParkingRwLock<Trie<H>>,
    pub weight: AtomicWeight,
    pub cumulative_weight: AtomicWeight,
    pub tip: Arc<ParkingRwLock<(Weight, u64, Multihash)>>,
    pub checkpoint: Arc<ParkingRwLock<(Weight, Multihash)>>,
}

impl<H: Hasher> BlockNode<H> {
    pub fn new(
        block: Block,
        witness: block::Witness,
        tip: Arc<ParkingRwLock<(Weight, u64, Multihash)>>,
        checkpoint: Arc<ParkingRwLock<(Weight, Multihash)>>,
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
            tip,
            checkpoint,
        }
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn on_block_parent_valid(&self, parent: &BlockNode<H>) -> bool {
        let parent_trie = parent.trie.read();

        if !self
            .block
            .verify_proposer_weight::<H>(&self.witness, parent_trie.root_hash())
        {
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
        let weight = self.weight.load(Ordering::Relaxed);
        let cumulative_weight = self.cumulative_weight.load(Ordering::Relaxed);
        let id = self.id();

        let tip = self.tip.read();

        if tip.0 < weight || tip.1 < cumulative_weight || tip.2 > id {
            drop(tip);
            let mut tip = self.tip.write();
            *tip = (weight, cumulative_weight, id);
        }

        let checkpoint = self.checkpoint.read();

        if (checkpoint.0 as f64) * 0.67 < weight as f64 {
            drop(checkpoint);
            let mut checkpoint = self.checkpoint.write();
            *checkpoint = (weight, id);
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
