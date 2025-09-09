use multihash_derive::MultihashDigest;

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub id: Multihash,
    pub value: Vec<u8>,
    pub script_pk: Vec<u8>,
}

impl Token {
    pub fn new(
        first_input_id: &Multihash,
        idx: u32,
        value: impl Into<Vec<u8>>,
        script_pk: impl Into<Vec<u8>>,
    ) -> Self {
        let value = value.into();
        let script_pk = script_pk.into();

        let mut buf = Vec::new();
        buf.extend(first_input_id.to_bytes());
        buf.extend(&idx.to_le_bytes());
        buf.extend_from_slice(&value);
        buf.extend_from_slice(&script_pk);
        let id = Hasher::default().digest(&buf);

        Self {
            id,
            value,
            script_pk,
        }
    }

    pub fn validate_id(&self, first_input_id: &Multihash, idx: u32) -> bool {
        let mut buf = Vec::new();
        buf.extend(first_input_id.to_bytes());
        buf.extend(&idx.to_le_bytes());
        buf.extend_from_slice(&self.value);
        buf.extend_from_slice(&self.script_pk);
        let id = Hasher::default().digest(&buf);
        id == self.id
    }
}
