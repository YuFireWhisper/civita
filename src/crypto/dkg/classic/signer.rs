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

    pub fn add_peers(&mut self, peers: HashMap<PeerId, u16>) {
        self.peers.extend(peers);
    }

    pub fn sign<H: Digest + Clone>(&self, seed: &[u8], message: &[u8]) -> Signature {
        let nonce = Self::generate_nonce(seed);
        let random_pub_key = Self::calculate_random_public_key(&nonce);
        let challenge = Self::compute_challenge::<H>(
            message,
            &random_pub_key.to_bytes(true),
            &self.public_key.to_bytes(true),
        );
        let s = self.calculate_signature(&nonce, &challenge);

        Signature::new()
            .with_signature(s)
            .with_random_public_key(random_pub_key)
    }

    fn generate_nonce(seed: &[u8]) -> Scalar<E> {
        let b = BigInt::from_bytes(seed);
        Scalar::from_bigint(&b)
    }

    fn calculate_random_public_key(k: &Scalar<E>) -> Point<E> {
        Point::generator() * k
    }

    fn compute_challenge<H: Digest + Clone>(
        message: &[u8],
        random_pk: &[u8],
        pub_key: &[u8],
    ) -> Scalar<E> {
        let input = [message, random_pk, pub_key].concat();
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
        let random_pk_bytes = signature.random_public_key_bytes();
        let index = self.get_peer_index(&peer).expect("Unknown peer");
        let signatures = self.processing.entry(random_pk_bytes.to_vec()).or_default();
        signatures.insert(index, signature.signature());

        (signatures.len() == self.threshold as usize)
            .then(|| self.finalize_signature::<H>(random_pk_bytes))
    }

    fn get_peer_index(&self, peer: &PeerId) -> Option<u16> {
        self.peers.get(peer).copied()
    }

    fn finalize_signature<H: Digest + Clone>(&mut self, random_pk_bytes: &[u8]) -> Signature {
        let signatures = self
            .processing
            .remove(random_pk_bytes)
            .expect("Unknown random public key");
        let points = signatures
            .keys()
            .map(|&i| Scalar::from(i))
            .collect::<Vec<_>>();
        let scalars = signatures.values().cloned().collect::<Vec<_>>();
        let final_signature =
            VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &scalars);

        Signature::new().with_signature(final_signature)
    }
}
