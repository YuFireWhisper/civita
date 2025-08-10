use std::sync::OnceLock;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use dashmap::{DashMap, DashSet};
use derivative::Derivative;
use parking_lot::RwLock as ParkingRwLock;

use crate::{
    consensus::block::{self, tree::node::ProposalNode, Block},
    crypto::{Hasher, Multihash},
    utils::{trie::Trie, Operation, Record},
};

#[derive(Serialize)]
struct SerializedBlockNode<T: Record> {
    block: Block,
    witness: block::Witness,
    trie_root: Multihash,
    cumulative_weight: T::Weight,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct BlockNode<H, T: Record> {
    block: Block,
    witness: block::Witness,
    trie: ParkingRwLock<Trie<H, T>>,
    trie_root: OnceLock<Multihash>,
    cumulative_weight: ParkingRwLock<T::Weight>,
    operations: DashMap<Vec<u8>, T::Operation>,
    existing_keys: DashMap<Vec<u8>, bool>,
    proposal_dependencies: DashSet<Multihash>,
}

impl<H: Hasher, T: Record> BlockNode<H, T> {
    pub fn genesis() -> Self {
        Self::default()
    }

    pub fn new(block: Block, witness: block::Witness) -> Self {
        Self {
            block,
            witness,
            ..Default::default()
        }
    }

    pub fn id(&self) -> Multihash {
        self.block.hash::<H>()
    }

    pub fn parents(&self) -> Vec<Multihash> {
        self.block
            .proposals
            .iter()
            .chain(std::iter::once(&self.block.parent))
            .copied()
            .collect()
    }

    pub fn on_block_parent_valid(&self, parent: &Self) -> bool {
        if self.block.height != parent.block.height + 1 {
            return false;
        }

        let mut trie = parent.trie.read().clone();
        let pk_hash = self.block.proposer_pk.to_hash::<H>().to_bytes();
        let witness = &self.witness;

        if !trie.expand(std::iter::once(pk_hash.as_slice()), &witness.proofs) {
            return false;
        }

        let weight = trie.get(&pk_hash).map(|v| v.weight()).unwrap_or_default();
        let cumulative_weight = *parent.cumulative_weight.read() + weight;

        *self.trie.write() = trie;
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

        self.trie.write().expand(
            parent.proposal.operations.keys().map(|k| k.as_slice()),
            &parent.witness.proofs,
        );

        *self.cumulative_weight.write() += parent.proposer_weight();
        parent.proposal.operations.iter().for_each(|(k, o)| {
            self.operations.insert(k.clone(), o.clone());
        });

        true
    }

    pub fn validate(&self) -> bool {
        let mut trie = self.trie.write();

        if !trie.apply_operations(
            self.operations
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone())),
            Some(&self.witness.proofs),
        ) {
            return false;
        }

        let root_hash = trie.root_hash();
        self.trie_root
            .set(root_hash)
            .expect("Root hash should be set only once");

        true
    }

    pub fn trie_root(&self) -> Multihash {
        self.trie_root
            .get()
            .cloned()
            .expect("Trie root should be set after validation")
    }
}

impl<H, T: Record> Clone for BlockNode<H, T> {
    fn clone(&self) -> Self {
        let trie_root = OnceLock::new();
        if let Some(root) = self.trie_root.get() {
            trie_root
                .set(*root)
                .expect("Trie root should be set only once");
        }

        Self {
            block: self.block.clone(),
            witness: self.witness.clone(),
            trie: ParkingRwLock::new(self.trie.read().clone()),
            trie_root,
            cumulative_weight: ParkingRwLock::new(*self.cumulative_weight.read()),
            operations: self.operations.clone(),
            existing_keys: self.existing_keys.clone(),
            proposal_dependencies: self.proposal_dependencies.clone(),
        }
    }
}

impl<H: Hasher, T: Record> Serialize for BlockNode<H, T> {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        SerializedBlockNode::<T> {
            block: self.block.clone(),
            witness: self.witness.clone(),
            trie_root: self.trie.read().root_hash(),
            cumulative_weight: *self.cumulative_weight.read(),
        }
        .to_writer(writer);
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, civita_serialize::Error> {
        let serialized: SerializedBlockNode<T> = Serialize::from_reader(reader)?;
        Ok(Self {
            block: serialized.block,
            witness: serialized.witness,
            trie: ParkingRwLock::new(Trie::from_root(serialized.trie_root)),
            cumulative_weight: ParkingRwLock::new(serialized.cumulative_weight),
            ..Default::default()
        })
    }
}
