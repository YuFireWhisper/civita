use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    utils::{trie::Trie, Record},
};

pub mod tree;

pub use tree::Tree;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Block {
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: u32,
    pub proposals: BTreeSet<Multihash>,
    pub proposer_pk: PublicKey,
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

#[derive(Default)]
pub struct Builder {
    parent: Option<Multihash>,
    checkpoint: Option<Multihash>,
    proposals: BTreeSet<Multihash>,
    proposer_pk: Option<PublicKey>,
}

impl Block {
    pub fn new(
        parent: Multihash,
        checkpoint: Multihash,
        proposals: BTreeSet<Multihash>,
        proposer_pk: PublicKey,
    ) -> Self {
        Block {
            parent,
            checkpoint,
            height: 0,
            proposals,
            proposer_pk,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_proofs<H: Hasher, T: Record>(
        &self,
        trie: &Trie<H, T>,
    ) -> HashMap<Multihash, Vec<u8>> {
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

    pub fn get_proposer_weight<H: Hasher, T: Record>(&self, trie: &Trie<H, T>) -> T::Weight {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        trie.get(&key).map(|v| v.weight()).unwrap_or_default()
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
        Self::default()
    }

    pub fn with_parent_block<H: Hasher>(mut self, parent: &Block) -> Self {
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

    pub fn build(self) -> Block {
        let parent = self.parent.expect("Parent block must be set");
        let checkpoint = self.checkpoint.expect("Checkpoint must be set");
        let proposals = self.proposals;
        let proposer_pk = self.proposer_pk.expect("Proposer public key must be set");

        Block::new(parent, checkpoint, proposals, proposer_pk)
    }
}

impl Default for Witness {
    fn default() -> Self {
        let block = Block::default();
        let sig = SecretKey::default().sign(&block.to_vec());

        Witness {
            sig,
            proofs: HashMap::new(),
            vdf_proof: Vec::new(),
        }
    }
}
