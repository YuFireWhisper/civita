use std::collections::HashSet;

use mockall::automock;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::algebra::{Point, Scalar},
    mocks::MockError,
    utils::IndexedMap,
};

pub mod schnorr;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum SignatureError {
    #[error("Failed to encode: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("Failed to decode: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Signature {
    Schnorr(schnorr::signature::Signature),
}

#[derive(Debug)]
pub enum SignResult {
    Success(Signature),
    Failure(HashSet<libp2p::PeerId>),
}

#[automock(type Error=MockError;)]
#[async_trait::async_trait]
pub trait Tss: Send + Sync {
    type Error: std::error::Error;

    async fn set_keypair(
        &mut self,
        secret_key: Scalar,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<(), Self::Error>;
    async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Result<SignResult, Self::Error>;
}

impl Signature {
    pub fn verify(&self, msg: &[u8], public_key: &Point) -> bool {
        match self {
            Signature::Schnorr(sig) => sig.verify(msg, public_key),
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, SignatureError> {
        self.try_into()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        Self::try_from(bytes)
    }
}

impl TryFrom<&Signature> for Vec<u8> {
    type Error = SignatureError;

    fn try_from(signature: &Signature) -> Result<Self, Self::Error> {
        bincode::serde::encode_to_vec(signature, bincode::config::standard())
            .map_err(SignatureError::from)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(sig, _)| sig)
            .map_err(SignatureError::from)
    }
}
