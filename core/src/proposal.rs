use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
    utils::mpt::{self, MerklePatriciaTrie, Node},
};

type ProofDb = HashMap<Multihash, Vec<u8>>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Diff {
    pub from: resident::Record,
    pub to: resident::Record,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Payload {
    pub code: u8,
    pub parent_root: Multihash,
    pub diff: BTreeMap<Vec<u8>, Diff>,
    pub total_stakes_diff: i32,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proposal_stakes: u32,

    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Witness {
    pub sig: Signature,
    pub proofs: ProofDb,
    pub vdf_proof: Vec<u8>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Proposal {
    pub payload: Payload,
    pub witness: Witness,
}

impl Payload {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn sign<H: Hasher>(&self, sk: &SecretKey) -> Signature {
        sk.sign(&self.hash::<H>().to_bytes())
    }
}

impl Witness {
    pub fn new(sig: Signature, proofs: ProofDb, vdf_proof: Vec<u8>) -> Self {
        Self {
            sig,
            proofs,
            vdf_proof,
        }
    }

    pub fn verify<H: Hasher, S: mpt::Storage>(
        &self,
        payload: &Payload,
        root_hash: Multihash,
        vdf_difficulty: u64,
        vdf: WesolowskiVDF,
        mpt: &MerklePatriciaTrie<H, S>,
    ) -> bool {
        if payload.parent_root != root_hash {
            return false;
        }

        let hash = payload.hash::<H>().to_bytes();

        if !payload.proposer_pk.verify_signature(&hash, &self.sig) {
            return false;
        }

        if vdf.verify(&hash, vdf_difficulty, &self.vdf_proof).is_err() {
            return false;
        }

        if !self.verify_proposer(payload, mpt) {
            return false;
        }

        if !self.verify_diff(payload, mpt) {
            return false;
        }

        true
    }

    fn verify_proposer<H: Hasher, S: mpt::Storage>(
        &self,
        payload: &Payload,
        mpt: &MerklePatriciaTrie<H, S>,
    ) -> bool {
        let key = payload.proposer_pk.to_hash::<H>().to_bytes();

        let Some(Node::Value(bytes)) = mpt.verify_proof(&key, &self.proofs) else {
            return false;
        };

        let record = resident::Record::from_slice(&bytes)
            .expect("Bytes is from root hash, it should be valid");

        record.stakes == payload.proposal_stakes
    }

    fn verify_diff<H: Hasher, S: mpt::Storage>(
        &self,
        payload: &Payload,
        mpt: &MerklePatriciaTrie<H, S>,
    ) -> bool {
        for (key, diff) in &payload.diff {
            let Some(Node::Value(bytes)) = mpt.verify_proof(key, &self.proofs) else {
                return false;
            };

            let record = resident::Record::from_slice(&bytes)
                .expect("Bytes is from root hash, it should be valid");

            if record != diff.from {
                return false;
            }
        }

        true
    }
}

impl Proposal {
    pub fn new(payload: Payload, witness: Witness) -> Self {
        Self { payload, witness }
    }

    pub fn verify<H: Hasher, S: mpt::Storage>(
        &self,
        root_hash: Multihash,
        vdf_difficulty: u64,
        vdf: WesolowskiVDF,
        mpt: &MerklePatriciaTrie<H, S>,
    ) -> bool {
        self.witness
            .verify(&self.payload, root_hash, vdf_difficulty, vdf, mpt)
    }
}
