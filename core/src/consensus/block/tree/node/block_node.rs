use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use civita_serialize_derive::Serialize;
use dashmap::{DashMap, DashSet};
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{
        self,
        tree::{dag::Node, node::ProposalNode, Mode},
        Block,
    },
    crypto::{Hasher, Multihash},
    utils::{trie::Trie, Operation, Record},
};

#[derive(Clone)]
#[derive(Serialize)]
pub struct SerializedBlockNode<T: Record> {
    pub block: Block,
    pub witness: block::Witness,
    pub trie_root: Multihash,
    pub trie_guide: HashMap<Multihash, Vec<u8>>,
    pub height: u64,
    pub weight: T::Weight,
    pub cumulative_weight: T::Weight,
}

pub struct BlockNode<H, T: Record> {
    pub block: Block,
    pub witness: block::Witness,
    pub trie: ParkingRwLock<Trie<H, T>>,
    pub height: AtomicU64,
    pub weight: ParkingRwLock<T::Weight>,
    pub cumulative_weight: ParkingRwLock<T::Weight>,
    pub mode: Arc<Mode>,
    pub existing_keys: DashMap<Vec<u8>, bool>,
    pub proposal_dependencies: DashSet<Multihash>,
    pub operations: DashMap<Vec<u8>, T::Operation>,
    pub proofs: DashMap<Multihash, Vec<u8>>,
    pub validated: AtomicBool,
}

impl<H: Hasher, T: Record> BlockNode<H, T> {
    pub fn new(block: Block, witness: block::Witness, mode: Arc<Mode>) -> Self {
        let trie = Trie::empty();

        Self {
            block,
            witness,
            trie: ParkingRwLock::new(trie),
            mode,
            height: Default::default(),
            weight: Default::default(),
            cumulative_weight: Default::default(),
            operations: DashMap::new(),
            existing_keys: DashMap::new(),
            proposal_dependencies: DashSet::new(),
            proofs: DashMap::new(),
            validated: AtomicBool::new(false),
        }
    }

    pub fn from_serialized(serialized: SerializedBlockNode<T>, mode: Arc<Mode>) -> Option<Self> {
        let keys = match mode.as_ref() {
            Mode::Normal(keys) => keys,
            _ => panic!("Cannot create BlockNode from serialized data in non-normal mode"),
        };

        let mut trie = Trie::empty();
        if !trie.expand(keys, &serialized.trie_guide) {
            return None;
        }

        let weight = ParkingRwLock::new(serialized.weight);
        let cumulative_weight = ParkingRwLock::new(serialized.cumulative_weight);

        Some(Self {
            block: serialized.block,
            witness: serialized.witness,
            trie: ParkingRwLock::new(trie),
            height: AtomicU64::new(serialized.height),
            weight,
            cumulative_weight,
            mode,
            operations: DashMap::new(),
            existing_keys: DashMap::new(),
            proposal_dependencies: DashSet::new(),
            proofs: DashMap::new(),
            validated: AtomicBool::new(false),
        })
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn on_block_parent_valid(&self, parent: &Self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;

        let witness = &self.witness;

        let mut trie = parent.trie.read().clone();
        let pk_hash = self.block.proposer_pk.to_hash::<H>().to_bytes();

        if !trie.expand(std::iter::once(pk_hash.as_slice()), &witness.proofs) {
            return false;
        }

        let height = parent.height.load(Relaxed).wrapping_add(1);
        let weight = self.block.get_proposer_weight(&trie);
        let cumulative_weight = *parent.cumulative_weight.read() + weight;

        self.height.store(height, Relaxed);
        *self.trie.write() = trie;
        *self.weight.write() += weight;
        *self.cumulative_weight.write() += cumulative_weight;

        true
    }

    pub fn on_proposal_parent_valid(&self, parent: &ProposalNode<T>) -> bool {
        if parent.proposal.dependencies.is_empty() {
            if parent
                .proposal
                .operations
                .keys()
                .any(|k| self.existing_keys.get(k).is_some_and(|dep| *dep.value()))
            {
                return false;
            }

            parent.proposal.operations.iter().for_each(|(k, o)| {
                self.existing_keys
                    .insert(k.clone(), o.is_order_dependent(k));
            });
        } else {
            if parent
                .proposal
                .dependencies
                .iter()
                .any(|key| self.proposal_dependencies.contains(key))
            {
                return false;
            }

            parent.proposal.dependencies.iter().for_each(|key| {
                self.proposal_dependencies.insert(*key);
            });
        }

        if self.trie.read().root.is_empty() {
            parent.witness.proofs.iter().for_each(|(k, v)| {
                self.proofs.insert(*k, v.clone());
            });
        } else {
            self.trie.write().expand(
                parent.proposal.operations.keys().map(|k| k.as_slice()),
                &parent.witness.proofs,
            );
        }

        let weight = *parent.proposer_weight.read();

        *self.weight.write() += weight;
        *self.cumulative_weight.write() += weight;
        parent.proposal.operations.iter().for_each(|(k, o)| {
            self.operations.insert(k.clone(), o.clone());
        });

        true
    }

    pub fn validate(&self) -> bool {
        if !self.validated.fetch_or(true, Ordering::Relaxed) {
            return true;
        }

        let mut trie = self.trie.write();

        if !trie.apply_operations(
            self.operations
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone())),
            Some(&self.witness.proofs),
        ) {
            return false;
        }

        if let Mode::Normal(keys) = self.mode.as_ref() {
            trie.retain(keys.iter().map(|k| k.as_slice()));
        }

        true
    }

    pub fn to_serialized<'a, I, U>(&self, keys: I) -> Option<SerializedBlockNode<T>>
    where
        I: IntoIterator<Item = U>,
        U: AsRef<[u8]> + 'a,
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
            weight: *self.weight.read(),
            cumulative_weight: *self.cumulative_weight.read(),
        })
    }
}

impl<H, T: Record> Clone for BlockNode<H, T> {
    fn clone(&self) -> Self {
        Self {
            block: self.block.clone(),
            witness: self.witness.clone(),
            trie: ParkingRwLock::new(self.trie.read().clone()),
            height: AtomicU64::new(self.height.load(Ordering::Relaxed)),
            weight: ParkingRwLock::new(*self.weight.read()),
            cumulative_weight: ParkingRwLock::new(*self.cumulative_weight.read()),
            mode: self.mode.clone(),
            operations: self.operations.clone(),
            existing_keys: self.existing_keys.clone(),
            proposal_dependencies: self.proposal_dependencies.clone(),
            proofs: self.proofs.clone(),
            validated: AtomicBool::new(self.validated.load(Ordering::Relaxed)),
        }
    }
}

impl<H: Hasher, T: Record> Node for BlockNode<H, T> {
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
