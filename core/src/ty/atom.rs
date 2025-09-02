use std::collections::{HashMap, HashSet};

use civita_serialize_derive::Serialize;

use crate::{crypto::Multihash, ty::token::Token};

pub type Height = u32;
pub type Timestamp = u64;

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Header {
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: Height,
    pub timestamp: Timestamp,
    pub body_hash: Multihash,
}

#[derive(Clone)]
#[derive(Serialize)]
pub struct Command {
    pub code: u8,
    pub input: HashSet<Multihash>,
    pub consumed: HashSet<Multihash>,
    pub created: Vec<Token>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Witness {
    pub vdf_proof: Vec<u8>,
    pub trie_proofs: HashMap<Multihash, Vec<u8>>,
    pub script_sigs: HashMap<Multihash, Vec<u8>>,
    pub atoms: Vec<Multihash>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Body {
    pub cmd: Option<Command>,
    pub witness: Witness,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Atom {
    pub hash: Multihash,
    pub header: Header,
    pub body: Body,
}
