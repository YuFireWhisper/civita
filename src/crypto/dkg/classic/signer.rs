use std::collections::HashMap;

use curv::{
    arithmetic::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use libp2p::PeerId;
use sha2::Digest;

use crate::crypto::dkg::classic::Signature;

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
            .entry(signature.random_public_key_bytes().to_vec())
            .or_default();
        let index = *self.peers.get(&peer).expect("peer not found");
        signatures.insert(index, signature.signature());

        if signatures.len() == self.threshold as usize {
            let points = signatures
                .keys()
                .map(|&i| Scalar::from(i))
                .collect::<Vec<_>>();
            let scalars = signatures.values().cloned().collect::<Vec<_>>();
            let final_signature =
                VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &scalars);

            self.processing.remove(signature.random_public_key_bytes());

            Some(signature.with_signature(final_signature))
        } else {
            None
        }
    }
}
