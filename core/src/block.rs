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

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0:?}")]
    Vdf(vdf::InvalidIterations),

    #[error(transparent)]
    Mpt(#[from] mpt::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Payload {
    pub proposals: HashSet<Multihash>,
    pub parent: Multihash,
    pub height: u64,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proposal_stakes: u32,

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

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Block {
    pub payload: Payload,
    pub witness: Witness,
}

impl Payload {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }
}

impl Witness {
    pub fn from_payload<H: Hasher, S: Storage>(
        payload: &Payload,
        sk: &SecretKey,
        vdf: WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: Trie<H, S>,
    ) -> Result<Self> {
        let hash = payload.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = HashMap::new();
        let key = payload.proposer_pk.to_hash::<H>().to_bytes();

        mpt.prove(&key, &mut proofs)?;

        let vdf_proof = vdf
            .solve(&payload.parent.to_bytes(), vdf_difficulty)
            .expect("VDF solve failed");

        Ok(Self {
            sig,
            proofs,
            vdf_proof,
        })
    }

    pub fn verify<H: Hasher>(
        &self,
        payload: &Payload,
        vdf: WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: Trie<H, impl Storage>,
    ) -> bool {
        let hash = payload.hash::<H>().to_bytes();

        if !payload.proposer_pk.verify_signature(&hash, &self.sig) {
            return false;
        }

        if vdf.verify(&hash, vdf_difficulty, &self.vdf_proof).is_err() {
            return false;
        }

        let key = payload.proposer_pk.to_hash::<H>().to_bytes();

        let Some(ProofResult::Exists(bytes)) = mpt.verify_proof(&key, &self.proofs) else {
            return false;
        };

        let record = resident::Record::from_slice(&bytes)
            .expect("Bytes is from root hash, it should be valid");

        record.stakes == payload.proposal_stakes
    }
}

impl Block {
    pub fn new(payload: Payload, witness: Witness) -> Self {
        Self { payload, witness }
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        self.payload.hash::<H>()
    }

    pub fn verify<H: Hasher, S: Storage>(
        &self,
        vdf: WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: Trie<H, S>,
    ) -> bool {
        self.witness.verify(&self.payload, vdf, vdf_difficulty, mpt)
    }
}
