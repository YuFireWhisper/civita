use serde::{Deserialize, Serialize};

use crate::crypto::{
    algebra::{Point, Scalar},
    tss::{self, schnorr},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct Signature {
    pub sig: Scalar,
    pub public_random: Point,
}

impl Signature {
    pub fn new(sig: Scalar, global_random: Point) -> Self {
        Self {
            sig,
            public_random: global_random,
        }
    }

    pub fn verify(&self, msg: &[u8], public_key: &Point) -> bool {
        let scheme = self.sig.scheme();
        let left = match Point::generator(&scheme).mul(&self.sig) {
            Ok(left) => left,
            Err(_) => return false,
        };

        let challenge = match schnorr::calculate_challenge(msg, &self.public_random, public_key) {
            Ok(challenge) => challenge,
            Err(_) => return false,
        };

        let pe = match public_key.mul(&challenge) {
            Ok(pe) => pe,
            Err(_) => return false,
        };

        let right = match self.public_random.sub(&pe) {
            Ok(right) => right,
            Err(_) => return false,
        };

        left == right
    }
}

impl From<Signature> for tss::Signature {
    fn from(sig: Signature) -> Self {
        tss::Signature::Schnorr(sig)
    }
}

impl TryFrom<tss::Signature> for Signature {
    type Error = tss::SignatureError;

    fn try_from(sig: tss::Signature) -> Result<Self, Self::Error> {
        match sig {
            tss::Signature::Schnorr(sig) => Ok(sig),
        }
    }
}
