use crate::crypto::{
    primitives::algebra::{Point, Scalar},
    tss::schnorr,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
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

        let right = match self.public_random.add(&pe) {
            Ok(right) => right,
            Err(_) => return false,
        };

        left == right
    }
}
