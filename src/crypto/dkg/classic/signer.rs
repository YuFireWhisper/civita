use std::collections::HashMap;

use curv::elliptic::curves::{Curve, Point, Scalar};
use libp2p::PeerId;
use sha2::Digest;

use crate::crypto::dkg::classic::{config::ThresholdCounter, Signature};

pub struct Signer<E: Curve> {
    secret: Scalar<E>,
    public_key: Point<E>,
    peers: HashMap<PeerId, u16>,
    processing: HashMap<Vec<u8>, Vec<Signature<E>>>,
    threshold: u16,
    threshold_counter: Box<dyn ThresholdCounter>,
}

impl<E: Curve> Signer<E> {
    pub fn new(
        secret: Scalar<E>,
        public_key: Point<E>,
        threshold_counter: Box<dyn ThresholdCounter>,
    ) -> Self {
        let peers = HashMap::new();
        let processing = HashMap::new();
        let threshold = 0;

        Self {
            secret,
            public_key,
            peers,
            processing,
            threshold,
            threshold_counter,
        }
    }

    pub fn add_peers(&mut self, peers: HashMap<PeerId, u16>) {
        self.peers.extend(peers);
        self.threshold = self.threshold_counter.call(self.peers.len() as u16);
    }

    pub fn sign<H: Digest + Clone>(&self, seed: &[u8], message: &[u8]) -> Signature<E> {
        Signature::new()
            .with_keypair(self.secret.clone(), self.public_key.clone())
            .generate::<H>(seed, message)
    }

    pub fn update<H: Digest + Clone>(
        &mut self,
        mut signature: Signature<E>,
        peer: PeerId,
    ) -> Option<Signature<E>> {
        let index = self.get_peer_index(&peer).expect("Unknown peer");
        signature.set_index(index);

        let random_pk_bytes = signature
            .random_public_key_bytes()
            .expect("Missing random public key");
        let signatures = self.processing.entry(random_pk_bytes).or_default();

        if signatures.len() == (self.threshold - 1) as usize {
            return Some(signature.aggregate::<H>(signatures));
        }
        signatures.push(signature);

        None
    }

    fn get_peer_index(&self, peer: &PeerId) -> Option<u16> {
        self.peers.get(peer).copied()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    use libp2p::PeerId;
    use sha2::Sha256;

    use crate::crypto::dkg::classic::signer::Signer;

    const NUM_PEERS: u16 = 3;

    type E = Secp256k1;
    type H = Sha256;

    fn generate_peers(n: u16) -> HashMap<PeerId, u16> {
        (0..n)
            .map(|i| (PeerId::random(), i))
            .collect::<HashMap<_, _>>()
    }

    fn threshold_counter(n: u16) -> u16 {
        (2 * n / 3) + 1
    }

    #[test]
    fn create_current_items() {
        let scalar = Scalar::<E>::random();
        let point = Point::zero();
        let threshold_counter = Box::new(threshold_counter);

        let signer = Signer::new(scalar.clone(), point.clone(), threshold_counter);

        assert_eq!(signer.secret, scalar);
        assert_eq!(signer.public_key, point);
        assert!(signer.peers.is_empty());
        assert!(signer.processing.is_empty());
        assert_eq!(signer.threshold, 0);
    }

    #[test]
    fn same_peers() {
        let scalar = Scalar::<E>::random();
        let point = Point::zero();
        let threshold_counter_box = Box::new(threshold_counter);
        let mut signer = Signer::new(scalar, point, threshold_counter_box);

        let peers = generate_peers(NUM_PEERS);
        signer.add_peers(peers.clone());

        assert_eq!(signer.peers, peers);
        assert_eq!(signer.threshold, threshold_counter(NUM_PEERS));
    }

    #[test]
    fn return_signature_reachable_threshold() {
        const MESSAGE: &[u8] = b"test message";
        const SEED: &[u8] = b"test seed";

        let secret = Scalar::<E>::random();
        let public_key = Point::generator() * &secret;
        let threshold_counter = Box::new(threshold_counter);
        let mut signer = Signer::<E>::new(secret, public_key, threshold_counter);

        let peers = generate_peers(NUM_PEERS);
        signer.add_peers(peers.clone());

        let initial_signature = signer.sign::<H>(SEED, MESSAGE);
        let peer_ids: Vec<PeerId> = peers.keys().copied().collect();
        let threshold = signer.threshold;

        let mut result = None;
        for (i, peer) in peer_ids.iter().enumerate() {
            result = signer.update::<H>(initial_signature.clone(), *peer);
            if i == threshold as usize - 1 {
                break;
            }
        }

        assert!(result.is_some());
    }
}
