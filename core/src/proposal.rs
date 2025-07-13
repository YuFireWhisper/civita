use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
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

impl Proposal {
    pub fn new(payload: Payload, witness: Witness) -> Self {
        Self { payload, witness }
    }

    pub fn verify_signature<H: Hasher>(&self) -> bool {
        let msg = self.payload.hash::<H>().to_bytes();
        self.payload
            .proposer_pk
            .verify_signature(&msg, &self.witness.sig)
    }
}
