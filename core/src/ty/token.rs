use std::sync::OnceLock;

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::crypto::{hasher::Hasher, Multihash};

#[derive(Serialize)]
pub struct Token {
    pub value: Vec<u8>,
    pub script_pk: Vec<u8>,

    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

impl Token {
    pub fn new(value: Vec<u8>, script_pk: Vec<u8>) -> Self {
        Self {
            value,
            script_pk,
            hash_cache: OnceLock::new(),
        }
    }

    pub fn hash(&self) -> Multihash {
        *self
            .hash_cache
            .get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}
