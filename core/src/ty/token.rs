use multihash_derive::MultihashDigest;

use crate::{
    crypto::{Hasher, Multihash},
    BINCODE_CONFIG,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub atom_id: Multihash,
    pub index: u32,
    pub value: Vec<u8>,
    pub script_pk: Vec<u8>,
}

impl Token {
    pub fn new(atom_id: Multihash, index: u32, value: Vec<u8>, script_pk: Vec<u8>) -> Self {
        Self {
            atom_id,
            index,
            value,
            script_pk,
        }
    }

    pub fn id(&self, hasher: Hasher) -> Multihash {
        let mut buf = Vec::with_capacity(self.atom_id.encoded_len() + 4);
        buf.extend(self.atom_id.to_bytes());
        buf.extend(&self.index.to_be_bytes());
        hasher.digest(&buf)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG).map(|(token, _)| token)
    }
}
