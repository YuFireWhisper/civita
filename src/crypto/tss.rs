use serde::{Deserialize, Serialize};

use crate::crypto::primitives::algebra::Point;

pub mod schnorr;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Signature {
    Schnorr(schnorr::signature::Signature),
}

pub trait Tss {
    type Error;

    fn sign(&self, seed: Option<&[u8]>, msg: &[u8]) -> Result<Signature, Self::Error>;
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool;
}

impl Signature {
    pub fn verify(&self, msg: &[u8], public_key: &Point) -> bool {
        match self {
            Signature::Schnorr(sig) => sig.verify(msg, public_key),
        }
    }
}
