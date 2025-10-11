use derivative::Derivative;

use crate::{traits::Config, BINCODE_CONFIG};

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token<T: Config> {
    pub value: T::Value,
    pub script_pk: T::ScriptPk,
}

impl<T: Config> Token<T> {
    pub fn new(value: T::Value, script_pk: T::ScriptPk) -> Self {
        Self { value, script_pk }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG).map(|(token, _)| token)
    }
}
