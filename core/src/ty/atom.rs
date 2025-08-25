use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::{
    crypto::{hasher::Hasher, Multihash},
    ty::token::Token,
};

pub type Height = u32;

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
pub struct Atom {
    pub height: Height,
    pub cmd: Option<Command>,
    pub timestamp: u64,

    #[serialize(skip)]
    cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Witness {
    pub vdf_proof: Vec<u8>,
    pub trie_proofs: HashMap<Multihash, Vec<u8>>,
    pub script_sigs: HashMap<Multihash, Vec<u8>>,
    pub atoms: HashSet<Multihash>,
}

impl Atom {
    pub fn hash(&self) -> Multihash {
        *self.cache.get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}
