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
    utils::trie::{self, ProofResult, Storage, Trie},
};

pub mod tree;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Mpt(#[from] trie::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Block {
    pub proposals: BTreeSet<Multihash>,
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
        mpt: Trie<H, S>,
        vdf_proof: Vec<u8>,
    ) -> Result<Witness> {
        let hash = self.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = HashMap::new();
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        mpt.prove(&key, &mut proofs)?;

        Ok(Witness {
            sig,
            proofs,
            vdf_proof,
        })
    }

    pub fn verify<H: Hasher>(
        &self,
        witness: &Witness,
        checkpoint: &Block,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
    ) -> bool {
        if self.parent_checkpoint != checkpoint.hash::<H>() || self.height <= checkpoint.height {
            return false;
        }

        let hash = self.hash::<H>().to_bytes();

        if !self.proposer_pk.verify_signature(&hash, &witness.sig) {
            return false;
        }

        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        if !self.verify_proof(&key, &witness.proofs, self.proposer_weight) {
            return false;
        }

        if !self.verify_vdf_proof::<H>(&key, vdf, &witness.vdf_proof, vdf_difficulty) {
            return false;
        }

        true
    }

    fn verify_proof(
        &self,
        key: &[u8],
        proofs: &HashMap<Multihash, Vec<u8>>,
        exp_weight: u32,
    ) -> bool {
        let Some(res) = trie::verify_proof_with_hash(key, proofs, self.parent) else {
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

    fn verify_vdf_proof<H: Hasher>(
        &self,
        key: &[u8],
        vdf: &WesolowskiVDF,
        vdf_proof: &[u8],
        vdf_difficulty: u64,
    ) -> bool {
        let c = H::hash(&[self.parent.to_bytes().as_slice(), key].concat()).to_bytes();
        vdf.verify(&c, vdf_difficulty, vdf_proof).is_ok()
    }
}
