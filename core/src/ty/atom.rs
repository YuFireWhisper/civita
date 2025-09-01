use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use libp2p::PeerId;

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
#[derive(Serialize)]
pub struct Atom {
    pub checkpoint: Multihash,
    pub peer: PeerId,
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
    pub atoms: Vec<Multihash>,
}

impl Atom {
    pub fn new(checkpoint: Multihash, peer: PeerId, cmd: Option<Command>, timestamp: u64) -> Self {
        Self {
            checkpoint,
            peer,
            cmd,
            timestamp,
            cache: OnceLock::new(),
        }
    }

    pub fn hash(&self) -> Multihash {
        *self.cache.get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}

impl Default for Atom {
    fn default() -> Self {
        Self {
            checkpoint: Multihash::default(),
            peer: PeerId::from_multihash(Multihash::default()).unwrap(),
            cmd: None,
            timestamp: 0,
            cache: OnceLock::new(),
        }
    }
}
