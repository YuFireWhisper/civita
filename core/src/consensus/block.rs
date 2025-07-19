use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
    utils::trie::{self, ProofResult, Trie},
};

pub(crate) mod tree;

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
    pub parent_checkpoint: Multihash,
    pub height: u64,
    pub proposals: BTreeSet<Multihash>,
    pub proposer_pk: PublicKey,
    pub proposer_weight: u32,
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
    parent_checkpoint: Option<Multihash>,
    height: Option<u64>,
    proposals: BTreeSet<Multihash>,
    proposer_pk: Option<PublicKey>,
    proposer_weight: Option<u32>,
}

impl Block {
    pub fn new(
        parent: Multihash,
        parent_checkpoint: Multihash,
        height: u64,
        proposer_pk: PublicKey,
        proposer_weight: u32,
    ) -> Self {
        Block {
            parent,
            parent_checkpoint,
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

    pub fn generate_witness<H: Hasher>(
        &self,
        sk: &SecretKey,
        mpt: &Trie<H>,
        vdf_proof: Vec<u8>,
    ) -> Result<Witness> {
        let hash = self.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = HashMap::new();
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        assert!(mpt.prove(&key, &mut proofs), "Failed to generate proof");

        Ok(Witness::new(sig, proofs, vdf_proof))
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
        let c = self.generate_challenge::<H>();
        vdf.verify(&c, difficulty, &witness.vdf_proof).is_ok()
    }

    fn generate_challenge<H: Hasher>(&self) -> Vec<u8> {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        H::hash(&[self.parent.to_bytes().as_slice(), &key].concat()).to_bytes()
    }

    pub fn verify_proposer_weight<H: Hasher>(
        &self,
        witness: &Witness,
        trie_root: Multihash,
    ) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        match trie::verify_proof_with_hash(&key, &witness.proofs, trie_root) {
            ProofResult::Exists(resident_bytes) => {
                resident::Record::from_slice(&resident_bytes)
                    .expect("Bytes is from root hash, it should be valid")
                    .weight
                    == self.proposer_weight
            }
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
            parent_checkpoint: None,
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

    pub fn with_checkpoint<H: Hasher>(mut self, checkpoint: &Block) -> Self {
        self.parent_checkpoint = Some(checkpoint.hash::<H>());
        self
    }

    pub fn with_proposals<I>(mut self, proposals: I) -> Self
    where
        I: IntoIterator<Item = Multihash>,
    {
        self.proposals = proposals.into_iter().collect();
        self
    }

    pub fn with_proposer_pk(mut self, proposer_pk: PublicKey) -> Self {
        self.proposer_pk = Some(proposer_pk);
        self
    }

    pub fn with_proposer_weight(mut self, proposer_weight: u32) -> Self {
        self.proposer_weight = Some(proposer_weight);
        self
    }

    pub fn build(self) -> Block {
        let parent = self.parent.expect("Parent block must be set");
        let parent_checkpoint = self
            .parent_checkpoint
            .expect("Parent checkpoint must be set");
        let height = self.height.expect("Height must be set");
        let proposer_pk = self.proposer_pk.expect("Proposer public key must be set");
        let proposer_weight = self.proposer_weight.expect("Proposer weight must be set");

        Block::new(
            parent,
            parent_checkpoint,
            height,
            proposer_pk,
            proposer_weight,
        )
    }
}
