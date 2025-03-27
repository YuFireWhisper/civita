use std::collections::HashMap;

use curv::{
    arithmetic::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use libp2p::{gossipsub::MessageId, PeerId};
use sha2::Digest;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {}

#[derive(Debug)]
pub struct Signer<E: Curve> {
    secret: Scalar<E>,
    public_key: Point<E>,
    threshold: u16,
    peers: HashMap<PeerId, u16>,
    processing: HashMap<MessageId, HashMap<u16, Scalar<E>>>,
}

impl<E: Curve> Signer<E> {
    pub fn new(
        secret: Scalar<E>,
        public_key: Point<E>,
        threshold: u16,
        peers: HashMap<PeerId, u16>,
    ) -> Self {
        let processing = HashMap::new();
        Self {
            secret,
            public_key,
            threshold,
            peers,
            processing,
        }
    }

    pub fn sign<H: Digest + Clone>(&self, seed: &[u8], raw_msg: &[u8]) -> Scalar<E> {
        let k = Self::calculate_nonce(seed);
        let r = Self::calculate_random_public_key(&k);
        let e = Self::calculate_challenge_value::<H>(
            raw_msg,
            &r.to_bytes(true),
            &self.public_key.to_bytes(true),
        );
        &k + &(&e * &self.secret)
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

    pub fn update<H: Digest + Clone>(
        &mut self,
        message_id: MessageId,
        peer: PeerId,
        signature: Scalar<E>,
    ) -> Option<Scalar<E>> {
        let signatures = self.processing.entry(message_id.clone()).or_default();
        let index = *self.peers.get(&peer).expect("peer not found");
        signatures.insert(index, signature);

        if signatures.len() == self.threshold as usize {
            let points = signatures
                .keys()
                .map(|&i| Scalar::from(i))
                .collect::<Vec<_>>();
            let scalars = signatures.values().cloned().collect::<Vec<_>>();
            let signature = VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &scalars);

            self.processing.remove(&message_id);

            Some(signature)
        } else {
            None
        }
    }
}
