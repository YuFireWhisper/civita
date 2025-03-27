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

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::{Point, Scalar, Secp256k1};

    use crate::crypto::dkg::classic::Signature;

    type E = Secp256k1;

    #[test]
    fn return_default_signature() {
        let result = Signature::new();

        assert!(result.sig_bytes.is_empty());
        assert!(result.r_pub_key.is_empty());
    }

    #[test]
    fn same_signature() {
        let signature = Scalar::<E>::random();

        let result = Signature::new().with_signature(signature.clone());

        assert_eq!(result.signature(), signature);
    }

    #[test]
    fn same_random_public_key() {
        let random_public_key = Point::<E>::zero();

        let result = Signature::new().with_random_public_key(random_public_key.clone());

        assert_eq!(result.random_public_key(), random_public_key);
    }

    #[test]
    fn same_random_public_key_bytes() {
        let random_public_key = Point::<E>::zero();
        let expected = random_public_key.to_bytes(true).to_vec();
        let sig = Signature::new().with_random_public_key(random_public_key.clone());

        let result = sig.random_public_key_bytes();

        assert_eq!(result, expected);
    }
}
