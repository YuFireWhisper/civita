use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
#[derive(Encode, Decode)]
pub enum Request {
    DkgScalar(Vec<u8>),
    DkgShare(Vec<u8>),
    Raw(Vec<u8>), // For testing
}

impl TryInto<Vec<u8>> for Request {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for Request {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

#[cfg(test)]
mod tests {}
