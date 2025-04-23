use serde::{Deserialize, Serialize};

use crate::crypto::{
    index_map::IndexedMap,
    primitives::algebra::{Point, Scalar},
};

pub mod schnorr;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Signature {
    Schnorr(schnorr::signature::Signature),
}

#[async_trait::async_trait]
pub trait Tss: Send + Sync {
    type Error: std::error::Error;

    async fn set_keypair(
        &mut self,
        secret_key: Scalar,
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<(), Self::Error>;
    async fn sign(&self, id: Vec<u8>, msg: &[u8]) -> Result<Signature, Self::Error>;
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool;
}

impl Signature {
    pub fn verify(&self, msg: &[u8], public_key: &Point) -> bool {
        match self {
            Signature::Schnorr(sig) => sig.verify(msg, public_key),
        }
    }
}
