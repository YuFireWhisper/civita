use multihash_derive::MultihashDigest;

use crate::{
    crypto::{Hasher, Multihash},
    ty::{ScriptPk, Value},
    BINCODE_CONFIG,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub first_input_id: Multihash,
    pub index: u32,
    pub value: Value,
    pub script_pk: ScriptPk,
}

impl Token {
    pub fn new<T, U>(first_input_id: Multihash, index: u32, value: T, script_pk: U) -> Self
    where
        T: Into<Value>,
        U: Into<ScriptPk>,
    {
        Self {
            first_input_id,
            index,
            value: value.into(),
            script_pk: script_pk.into(),
        }
    }

    pub fn id(&self, hasher: Hasher) -> Multihash {
        let mut buf = Vec::with_capacity(self.first_input_id.encoded_len() + 4);
        buf.extend(self.first_input_id.to_bytes());
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
