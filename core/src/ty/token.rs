use civita_serialize_derive::Serialize;

use crate::crypto::Multihash;

#[derive(Clone)]
#[derive(Serialize)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub id: Multihash,
    pub value: Vec<u8>,
    pub script_pk: Vec<u8>,
}

// impl Token {
//     pub fn new(value: Vec<u8>, script_pk: Vec<u8>) -> Self {
//         Self {
//             value,
//             script_pk,
//             hash_cache: OnceLock::new(),
//         }
//     }
//
//     pub fn hash(&self) -> Multihash {
//         *self
//             .hash_cache
//             .get_or_init(|| Hasher::digest(&self.to_vec()))
//     }
// }
