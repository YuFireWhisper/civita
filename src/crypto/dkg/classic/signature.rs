use curv::elliptic::curves::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Signature {
    sig_bytes: Vec<u8>,
    r_pub_key: Vec<u8>,
}

impl Signature {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_signature<E: Curve>(mut self, signature: Scalar<E>) -> Self {
        self.sig_bytes = signature.to_bytes().to_vec();
        self
    }

    pub fn with_random_public_key<E: Curve>(mut self, random_public_key: Point<E>) -> Self {
        self.r_pub_key = random_public_key.to_bytes(true).to_vec();
        self
    }

    pub fn signature<E: Curve>(&self) -> Scalar<E> {
        Scalar::from_bytes(&self.sig_bytes)
            .expect("Invalid signature bytes, this should never happen")
    }

    pub fn random_public_key<E: Curve>(&self) -> Point<E> {
        Point::from_bytes(&self.r_pub_key)
            .expect("Invalid random public key bytes, this should never happen")
    }

    pub fn random_public_key_bytes(&self) -> &[u8] {
        &self.r_pub_key
    }
}
