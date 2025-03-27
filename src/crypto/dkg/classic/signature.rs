use curv::elliptic::curves::{Curve, Point, Scalar};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Signature {
    signature: Vec<u8>,
    random_public_key: Vec<u8>,
}

impl Signature {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_signature<E: Curve>(mut self, signature: Scalar<E>) -> Self {
        self.signature = signature.to_bytes().to_vec();
        self
    }

    pub fn with_random_public_key<E: Curve>(mut self, random_public_key: Point<E>) -> Self {
        self.random_public_key = random_public_key.to_bytes(true).to_vec();
        self
    }

    pub fn signature<E: Curve>(&self) -> Scalar<E> {
        Scalar::from_bytes(&self.signature)
            .expect("Invalid signature bytes, this should never happen")
    }

    pub fn random_public_key<E: Curve>(&self) -> Point<E> {
        Point::from_bytes(&self.random_public_key)
            .expect("Invalid random public key bytes, this should never happen")
    }

    pub fn random_public_key_bytes(&self) -> &[u8] {
        &self.random_public_key
    }
}
