use std::collections::HashMap;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::{crypto::Multihash, ty::token::Token};

pub type Height = u32;
pub type Timestamp = u64;

#[derive(Clone)]
#[derive(Serialize)]
pub struct Command {
    pub code: u8,
    pub inputs: Vec<Multihash>,
    pub created: Vec<Token>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
pub struct Atom {
    pub hash: Multihash,
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: Height,
    pub nonce: Vec<u8>,
    pub timestamp: Timestamp,
    pub cmd: Option<Command>,
    pub atoms: Vec<Multihash>,
    pub trie_proofs: HashMap<Multihash, Vec<u8>>,
    pub script_sigs: HashMap<Multihash, Vec<u8>>,
}

impl Atom {
    pub fn hash_input(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.parent.to_writer(&mut buf);
        self.checkpoint.to_writer(&mut buf);
        self.height.to_writer(&mut buf);
        self.nonce.to_writer(&mut buf);
        self.timestamp.to_writer(&mut buf);
        self.cmd.to_writer(&mut buf);
        self.atoms.to_writer(&mut buf);
        self.trie_proofs.to_writer(&mut buf);
        buf
    }

    pub fn vdf_input(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.parent.to_writer(&mut buf);
        self.checkpoint.to_writer(&mut buf);
        self.height.to_writer(&mut buf);
        self.timestamp.to_writer(&mut buf);
        self.cmd.to_writer(&mut buf);
        self.atoms.to_writer(&mut buf);
        self.trie_proofs.to_writer(&mut buf);
        buf
    }
}
