use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, Signature},
    utils::{
        trie::{self, ProofResult, Trie},
        Record,
    },
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
pub struct Block<T: Record> {
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub proposals: BTreeSet<Multihash>,
    pub proposer_pk: PublicKey,
    pub proposer_weight: T::Weight,
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

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Builder<T: Record> {
    parent: Option<Multihash>,
    checkpoint: Option<Multihash>,
    proposals: BTreeSet<Multihash>,
    proposer_pk: Option<PublicKey>,
    proposer_weight: Option<T::Weight>,
}

impl<T: Record> Block<T> {
    pub fn new(
        parent: Multihash,
        checkpoint: Multihash,
        proposals: BTreeSet<Multihash>,
        proposer_pk: PublicKey,
        proposer_weight: T::Weight,
    ) -> Self {
        Block {
            parent,
            checkpoint,
            proposals,
            proposer_pk,
            proposer_weight,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_proofs<H: Hasher>(&self, trie: &Trie<H, T>) -> HashMap<Multihash, Vec<u8>> {
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
        let challenge_bytes = [
            self.proposer_pk.to_hash::<H>().to_bytes(),
            self.parent.to_bytes(),
        ]
        .concat();

        let hash = H::hash(&challenge_bytes).to_bytes();

        // The veirfy function will panic if the proof is invalid. (I don't know why, but it is the
        // case).
        //
        // If we have time, we should implement own VDF Library, which will not panic on
        std::panic::catch_unwind(|| vdf.verify(&hash, difficulty, &witness.vdf_proof).is_ok())
            .unwrap_or(false)
    }

    pub fn verify_proposer_weight<H: Hasher>(
        &self,
        witness: &Witness,
        trie_root: Multihash,
    ) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        match trie::verify_proof_with_hash::<T>(&key, &witness.proofs, trie_root) {
            ProofResult::Exists(record) => record.weight() == self.proposer_weight,
            ProofResult::NotExists => self.proposer_weight == Default::default(),
            ProofResult::Invalid => false,
        }
    }

    pub fn verify_proposer_weight_with_proofs<H: Hasher>(
        &self,
        proofs: &HashMap<Multihash, Vec<u8>>,
        trie_root: Multihash,
    ) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        match trie::verify_proof_with_hash::<T>(&key, proofs, trie_root) {
            ProofResult::Exists(record) => record.weight() == self.proposer_weight,
            ProofResult::NotExists => self.proposer_weight == Default::default(),
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

impl<T: Record> Builder<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_parent_block<H: Hasher>(mut self, parent: &Block<T>) -> Self {
        self.parent = Some(parent.hash::<H>());
        self.checkpoint = Some(parent.checkpoint);
        self
    }

    pub fn with_parent_hash(mut self, parent: Multihash) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn with_checkpoint(mut self, checkpoint: Multihash) -> Self {
        self.checkpoint = Some(checkpoint);
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

    pub fn with_proposer_weight(mut self, proposer_weight: T::Weight) -> Self {
        self.proposer_weight = Some(proposer_weight);
        self
    }

    pub fn build(self) -> Block<T> {
        let parent = self.parent.expect("Parent block must be set");
        let checkpoint = self.checkpoint.expect("Checkpoint must be set");
        let proposals = self.proposals;
        let proposer_pk = self.proposer_pk.expect("Proposer public key must be set");
        let proposer_weight = self.proposer_weight.expect("Proposer weight must be set");

        Block::new(parent, checkpoint, proposals, proposer_pk, proposer_weight)
    }
}
