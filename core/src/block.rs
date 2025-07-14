use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize_derive::Serialize;

use crate::crypto::{Multihash, PublicKey, Signature};

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
