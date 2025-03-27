use std::collections::HashMap;

use curv::elliptic::curves::{
    bls12_381::{g1::G1Point, scalar::FieldScalar},
    Curve, ECPoint, ECScalar, Point, Scalar,
};
use libp2p::gossipsub::MessageId;
use sha2::Digest;

#[derive(Debug)]
pub struct Signer<E: Curve> {
    secret: Scalar<E>,
    public_key: Point<E>,
    threshold: u16,
    processing: HashMap<MessageId, Vec<G1Point>>,
}

impl<E: Curve> Signer<E> {
    pub fn new(secret: Scalar<E>, public_key: Point<E>, threshold: u16) -> Self {
        let processing = HashMap::new();
        Self {
            secret,
            public_key,
            threshold,
            processing,
        }
    }

    pub fn sign<H: Digest + Clone>(&self, raw_msg: &[u8]) -> G1Point {
        let msg = H::new().chain(raw_msg).finalize();
        let hash = G1Point::hash_to_curve(&msg);
        let field_scalar = FieldScalar::from_bigint(&self.secret.to_bigint());
        hash.scalar_mul(&field_scalar)
    }

    pub fn update(&mut self, message_id: MessageId, signature: G1Point) -> Option<G1Point> {
        let signatures = self.processing.entry(message_id.clone()).or_default();
        signatures.push(signature);

        if signatures.len() == self.threshold as usize {
            let aggregated = Self::aggregate_signatures(signatures.drain(..));
            self.processing.remove(&message_id);
            Some(aggregated)
        } else {
            None
        }
    }

    fn aggregate_signatures(signatures: impl IntoIterator<Item = G1Point>) -> G1Point {
        signatures
            .into_iter()
            .reduce(|acc, sig| acc.add_point(&sig))
            .expect("signatures is empty")
    }
}
