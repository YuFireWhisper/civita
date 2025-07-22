use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, Signature},
    utils::trie::{self, ProofResult, Trie, Weight},
};

pub mod tree;

pub use tree::Tree;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Block {
    pub parent: Multihash,
    pub height: u64,
    pub proposals: BTreeSet<Multihash>,
    pub proposer_pk: PublicKey,
    pub proposer_weight: Weight,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Witness {
    pub sig: Signature,
    pub proofs: HashMap<Multihash, Vec<u8>>,
    pub vdf_proof: Vec<u8>,
}

pub struct Builder {
    parent: Option<Multihash>,
    height: Option<u64>,
    proposals: BTreeSet<Multihash>,
    proposer_pk: Option<PublicKey>,
    proposer_weight: Option<Weight>,
}

impl Block {
    pub fn new(
        parent: Multihash,
        height: u64,
        proposer_pk: PublicKey,
        proposer_weight: Weight,
    ) -> Self {
        Block {
            parent,
            height,
            proposals: BTreeSet::new(),
            proposer_pk,
            proposer_weight,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_proofs<H: Hasher>(&self, trie: &Trie<H>) -> HashMap<Multihash, Vec<u8>> {
        let mut proofs = HashMap::new();
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        trie.prove(&key, &mut proofs);
        proofs
    }

    pub fn verify_signature<H: Hasher>(&self, witness: &Witness) -> bool {
        let hash = self.hash::<H>().to_bytes();
        self.proposer_pk.verify_signature(&hash, &witness.sig)
    }

    pub fn verify_vdf<H: Hasher>(
        &self,
        witness: &Witness,
        vdf: &WesolowskiVDF,
        difficulty: u64,
    ) -> bool {
        let hash = self.hash::<H>().to_bytes();
        vdf.verify(&hash, difficulty, &witness.vdf_proof).is_ok()
    }

    pub fn verify_proposer_weight_with_proofs<H: Hasher>(
        &self,
        proofs: &HashMap<Multihash, Vec<u8>>,
        trie_root: Multihash,
    ) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        match trie::verify_proof_with_hash(&key, proofs, trie_root) {
            ProofResult::Exists(record) => record.weight == self.proposer_weight,
            ProofResult::NotExists => self.proposer_weight == 0,
            ProofResult::Invalid => false,
        }
    }
}

impl Witness {
    pub fn new(sig: Signature, proofs: HashMap<Multihash, Vec<u8>>, vdf_proof: Vec<u8>) -> Self {
        Witness {
            sig,
            proofs,
            vdf_proof,
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            parent: None,
            height: None,
            proposals: BTreeSet::new(),
            proposer_pk: None,
            proposer_weight: None,
        }
    }

    pub fn with_parent_block<H: Hasher>(mut self, parent: &Block) -> Self {
        self.parent = Some(parent.hash::<H>());
        self.height = Some(parent.height.wrapping_add(1));
        self
    }

    pub fn with_parent_hash(mut self, parent: Multihash) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    pub fn with_proposals<I>(mut self, proposals: I) -> Self
    where
        I: IntoIterator<Item = Multihash>,
    {
        self.proposals.extend(proposals);
        self
    }

    pub fn with_proposer_pk(mut self, proposer_pk: PublicKey) -> Self {
        self.proposer_pk = Some(proposer_pk);
        self
    }

    pub fn with_proposer_weight(mut self, proposer_weight: Weight) -> Self {
        self.proposer_weight = Some(proposer_weight);
        self
    }

    pub fn build(self) -> Block {
        let parent = self.parent.expect("Parent block must be set");
        let height = self.height.expect("Height must be set");
        let proposer_pk = self.proposer_pk.expect("Proposer public key must be set");
        let proposer_weight = self.proposer_weight.expect("Proposer weight must be set");

        Block::new(parent, height, proposer_pk, proposer_weight)
    }
}
