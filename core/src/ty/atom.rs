use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use num_bigint::BigUint;

use crate::{crypto::Multihash, ty::token::Token, utils::mmr::MmrProof};

pub type Height = u32;
pub type Timestamp = u64;

#[derive(Clone)]
#[derive(Serialize)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum Input {
    Confirmed(Token, BigUint, MmrProof, Vec<u8>),
    Unconfirmed(Multihash, Vec<u8>),
}

#[derive(Clone)]
#[derive(Serialize)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Command {
    pub code: u8,
    pub inputs: Vec<Input>,
    pub created: Vec<Token>,
}

#[derive(Clone)]
#[derive(Default)]
#[derive(Serialize)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Atom {
    pub hash: Multihash,
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub height: Height,
    pub nonce: Vec<u8>,
    pub timestamp: Timestamp,
    pub cmd: Option<Command>,
    pub atoms: Vec<Multihash>,
}

impl Input {
    pub fn id(&self) -> &Multihash {
        match self {
            Input::Confirmed(t, ..) => &t.id,
            Input::Unconfirmed(id, ..) => id,
        }
    }
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
        buf
    }
}
