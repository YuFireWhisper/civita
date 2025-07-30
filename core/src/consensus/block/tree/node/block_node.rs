use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
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

#[derive(Clone)]
#[derive(Serialize)]
pub struct SerializedBlockNode {
    pub block: Block,
    pub witness: block::Witness,
    pub trie_root: Multihash,
    pub trie_guide: HashMap<Multihash, Vec<u8>>,
    pub height: u64,
    pub weight: Weight,
    pub cumulative_weight: Weight,
}

pub struct BlockNode<H> {
    pub block: Block,
    pub witness: block::Witness,
    pub trie: ParkingRwLock<Trie<H>>,
    pub height: AtomicU64,
    pub weight: AtomicWeight,
    pub cumulative_weight: AtomicWeight,
    pub mode: Arc<Mode>,
    pub finalized: AtomicBool,
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
            height: AtomicU64::new(0),
            weight,
            cumulative_weight,
            mode,
            finalized: AtomicBool::new(false),
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
            height: AtomicU64::new(serialized.height),
            weight,
            cumulative_weight,
            mode,
            finalized: AtomicBool::new(true),
        })
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn on_block_parent_valid(&self, parent: &BlockNode<H>) -> bool {
        use std::sync::atomic::Ordering::Relaxed;

        if self.finalized.load(Relaxed) {
            let height = parent.height.load(Relaxed).wrapping_add(1);
            self.height.store(height, Relaxed);
            return true;
        }

        let witness = &self.witness;
        let parent_trie = parent.trie.read();
        let root_hash = parent_trie.root_hash();
        if !self.block.verify_proposer_weight::<H>(witness, root_hash) {
            return false;
        }

        let height = parent.height.load(Relaxed).wrapping_add(1);
        let cumulative_weight = parent.cumulative_weight.load(Relaxed) + self.block.proposer_weight;

        *self.trie.write() = parent_trie.clone();

        self.height.store(height, Relaxed);
        self.weight.store(self.block.proposer_weight, Relaxed);
        self.cumulative_weight.store(cumulative_weight, Relaxed);

        true
    }

    pub fn on_proposal_parent_valid(&self, parent: &ProposalNode) -> bool {
        let prop = &parent.proposal;
        let witness = &parent.witness;
        let weight = parent.proposer_weight.load(Ordering::Relaxed);

        {
            let mut trie = self.trie.write();
            prop.apply_operations(&mut trie, witness);
        }

        self.weight.fetch_add(weight, Ordering::Relaxed);
        self.cumulative_weight.fetch_add(weight, Ordering::Relaxed);

        true
    }

    pub fn validate(&self) -> bool {
        self.trie.write().commit();

        if let Mode::Normal(keys) = self.mode.as_ref() {
            self.trie.write().retain(keys.iter().map(|k| k.as_slice()));
        }

        self.finalized.store(true, Ordering::Relaxed);

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
            height: self.height.load(Relaxed),
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
            height: AtomicU64::new(self.height.load(Ordering::Relaxed)),
            weight: AtomicWeight::new(self.weight.load(Ordering::Relaxed)),
            cumulative_weight: AtomicWeight::new(self.cumulative_weight.load(Ordering::Relaxed)),
            mode: self.mode.clone(),
            finalized: AtomicBool::new(self.finalized.load(Ordering::Relaxed)),
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
