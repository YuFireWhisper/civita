use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
};

use civita_serialize_derive::Serialize;
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        self,
        tree::{
            dag::Node,
            node::{AtomicWeight, ProposalNode},
            Mode,
        },
        Block,
    },
    crypto::{Hasher, Multihash},
    utils::trie::{Trie, Weight},
};

#[derive(Serialize)]
pub struct SerializedBlockNode {
    pub block: Block,
    pub witness: block::Witness,
    pub trie_root: Multihash,
    pub trie_guide: HashMap<Multihash, Vec<u8>>,
    pub weight: Weight,
    pub cumulative_weight: Weight,
}

pub struct BlockNode<H> {
    pub block: Block,
    pub witness: block::Witness,
    pub trie: ParkingRwLock<Trie<H>>,
    pub weight: AtomicWeight,
    pub cumulative_weight: AtomicWeight,
    pub mode: Arc<Mode>,
}

impl<H: Hasher> BlockNode<H> {
    pub fn new(block: Block, witness: block::Witness, mode: Arc<Mode>) -> Self {
        let trie = Trie::empty();
        let weight = AtomicWeight::default();
        let cumulative_weight = AtomicWeight::default();

        Self {
            block,
            witness,
            trie: ParkingRwLock::new(trie),
            weight,
            cumulative_weight,
            mode,
        }
    }

    pub fn from_serialized(serialized: SerializedBlockNode, mode: Arc<Mode>) -> Option<Self> {
        let keys = match mode.as_ref() {
            Mode::Normal(keys) => keys,
            _ => panic!("Cannot create BlockNode from serialized data in non-normal mode"),
        };

        let mut trie = Trie::empty();
        if !trie.expand(keys, &serialized.trie_guide) {
            return None;
        }

        let weight = AtomicWeight::new(serialized.weight);
        let cumulative_weight = AtomicWeight::new(serialized.cumulative_weight);

        Some(Self {
            block: serialized.block,
            witness: serialized.witness,
            trie: ParkingRwLock::new(trie),
            weight,
            cumulative_weight,
            mode,
        })
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn on_block_parent_valid(&self, parent: &BlockNode<H>) -> bool {
        let witness = &self.witness;
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

        true
    }

    pub fn trie_root_hash(&self) -> Multihash {
        self.trie.read().root_hash()
    }

    pub fn to_serialized<'a, I, T>(&self, keys: I) -> Option<SerializedBlockNode>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]> + 'a,
    {
        use std::sync::atomic::Ordering::Relaxed;

        let trie = self.trie.read();
        let trie_root = trie.root_hash();
        let trie_guide = trie.generate_guide(keys)?;

        Some(SerializedBlockNode {
            block: self.block.clone(),
            witness: self.witness.clone(),
            trie_root,
            trie_guide,
            weight: self.weight.load(Relaxed),
            cumulative_weight: self.cumulative_weight.load(Relaxed),
        })
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
            mode: self.mode.clone(),
        }
    }
}

impl<H: Hasher> Node for BlockNode<H> {
    type Id = Multihash;

    fn id(&self) -> Self::Id {
        self.id()
    }

    fn validate(&self) -> bool {
        self.validate()
    }

    fn on_parent_valid(&self, child: &Self) -> bool {
        self.on_block_parent_valid(child)
    }
}
