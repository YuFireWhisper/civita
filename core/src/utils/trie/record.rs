use civita_serialize_derive::Serialize;

use crate::utils::trie::Weight;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Record {
    pub weight: Weight,
    pub data: Vec<u8>,
}

impl Record {
    pub fn new(weight: Weight, data: Vec<u8>) -> Self {
        Self { weight, data }
    }
}
