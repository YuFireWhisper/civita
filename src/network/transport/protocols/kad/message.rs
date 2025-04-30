use serde::{Deserialize, Serialize};

use crate::{
    crypto::tss::Signature, network::transport::protocols::kad::Payload, traits::Byteable,
};

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(String),

    #[error("{0}")]
    Eecode(String),
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Message {
    payload: Vec<u8>,
    signature: Signature,
}

impl Message {
    pub fn new(payload: Payload, signature: Signature) -> Result<Self, Error> {
        let payload = payload.to_vec().map_err(|e| Error::Encode(e.to_string()))?;
        Ok(Self { payload, signature })
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    pub fn payload(&self) -> Result<Payload, Error> {
        Payload::from_slice(&self.payload).map_err(|e| Error::Eecode(e.to_string()))
    }
}
