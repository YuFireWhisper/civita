use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
    utils::mpt::{self, ProofResult, Storage, Trie},
};

pub mod tree;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Mpt(#[from] mpt::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Block {
    pub proposals: HashSet<Multihash>,
    pub parent: Multihash,
    pub parent_checkpoint: Multihash,
    pub height: u64,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
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

impl Block {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_witness<H: Hasher, S: Storage>(
        &self,
        sk: &SecretKey,
        vdf: WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: Trie<H, S>,
    ) -> Result<Witness> {
        let hash = self.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = HashMap::new();
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        mpt.prove(&key, &mut proofs)?;

        let vdf_proof = vdf
            .solve(&self.parent.to_bytes(), vdf_difficulty)
            .expect("VDF solve failed");

        Ok(Witness {
            sig,
            proofs,
            vdf_proof,
        })
    }

    pub fn verify<H: Hasher>(
        &self,
        witness: &Witness,
        parent: &Multihash,
        checkpoint: &Multihash,
    ) -> bool {
        if &self.parent != parent || &self.parent_checkpoint != checkpoint {
            return false;
        }

        let hash = self.hash::<H>().to_bytes();

        if !self.proposer_pk.verify_signature(&hash, &witness.sig) {
            return false;
        }

        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        self.verify_proof(&key, &witness.proofs, self.proposer_weight)
    }

    fn verify_proof(
        &self,
        key: &[u8],
        proofs: &HashMap<Multihash, Vec<u8>>,
        exp_weight: u32,
    ) -> bool {
        let Some(res) = mpt::verify_proof_with_hash(key, proofs, self.parent) else {
            return false;
        };

        let ProofResult::Exists(resident_bytes) = res else {
            // If the proof does not exist, we expect no record
            return exp_weight == 0;
        };

        let record = resident::Record::from_slice(&resident_bytes)
            .expect("Bytes is from root hash, it should be valid");

        record.weight == exp_weight
    }
}
