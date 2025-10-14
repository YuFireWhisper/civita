use crate::BINCODE_CONFIG;

#[derive(Clone)]
#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub value: Vec<u8>,
    pub script_pk: Vec<u8>,
}

impl Token {
    pub fn new(value: Vec<u8>, script_pk: Vec<u8>) -> Self {
        Self { value, script_pk }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, BINCODE_CONFIG).map(|(token, _)| token)
    }
}
