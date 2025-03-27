use std::collections::HashMap;

use curv::{
    arithmetic::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
}

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
        Scalar::from_bytes(&self.signature).expect("Invalid signature bytes, this should never happen")
    }

    pub fn random_public_key<E: Curve>(&self) -> Point<E> {
        Point::from_bytes(&self.random_public_key).expect("Invalid random public key bytes, this should never happen")
    }

    pub fn random_public_key_bytes(&self) -> &[u8] {
        &self.random_public_key
    }
}

#[derive(Debug)]
pub struct Signer<E: Curve> {
    secret: Scalar<E>,
    public_key: Point<E>,
    threshold: u16,
    peers: HashMap<PeerId, u16>,
    processing: HashMap<Vec<u8>, HashMap<u16, Scalar<E>>>,
}

impl<E: Curve> Signer<E> {
    pub fn new(secret: Scalar<E>, public_key: Point<E>, threshold: u16) -> Self {
        let peers = HashMap::new();
        let processing = HashMap::new();
        Self {
            secret,
            public_key,
            threshold,
            peers,
            processing,
        }
    }

    pub fn with_peers(mut self, peers: HashMap<PeerId, u16>) -> Self {
        self.peers.extend(peers);
        self
    }

    pub fn sign<H: Digest + Clone>(&self, seed: &[u8], raw_msg: &[u8]) -> Signature {
        let nonce = Self::calculate_nonce(seed);
        let random_pub_key = Self::calculate_random_public_key(&nonce);
        let challenge = Self::calculate_challenge_value::<H>(
            raw_msg,
            &random_pub_key.to_bytes(true),
            &self.public_key.to_bytes(true),
        );
        let s = Self::calculate_signature(self, &nonce, &challenge);

        Signature::new()
            .with_signature(s)
            .with_random_public_key(random_pub_key)
    }

    fn calculate_nonce(seed: &[u8]) -> Scalar<E> {
        let b = BigInt::from_bytes(seed);
        Scalar::from_bigint(&b)
    }

    fn calculate_random_public_key(k: &Scalar<E>) -> Point<E> {
        Point::generator() * k
    }

    fn calculate_challenge_value<H: Digest + Clone>(m: &[u8], r: &[u8], y: &[u8]) -> Scalar<E> {
        let input = [m, r, y].concat();
        let h = H::new().chain(&input).finalize();
        let b = BigInt::from_bytes(&h);
        Scalar::from_bigint(&b)
    }

    fn calculate_signature(&self, nonce: &Scalar<E>, challenge: &Scalar<E>) -> Scalar<E> {
        nonce + &(challenge * &self.secret)
    }

    pub fn update<H: Digest + Clone>(
        &mut self,
        signature: Signature,
        peer: PeerId,
    ) -> Option<Signature> {
        let signatures = self
            .processing
            .entry(signature.random_public_key.clone())
            .or_default();
        let index = *self.peers.get(&peer).expect("peer not found");
        signatures.insert(
            index,
            signature.signature()
        );

        if signatures.len() == self.threshold as usize {
            let points = signatures
                .keys()
                .map(|&i| Scalar::from(i))
                .collect::<Vec<_>>();
            let scalars = signatures.values().cloned().collect::<Vec<_>>();
            let final_signature =
                VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &scalars);

            self.processing.remove(&signature.random_public_key);

            Some(signature.with_signature(final_signature))
        } else {
            None
        }
    }
}
