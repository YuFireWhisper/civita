use std::collections::HashMap;

use curv::elliptic::curves::Curve;
use libp2p::PeerId;
use sha2::Digest;

use crate::crypto::dkg::classic::{config::ThresholdCounter, keypair::Keypair, Signature};

pub struct Signer<E: Curve> {
    keypair: Keypair<E>,
    peers: HashMap<PeerId, u16>,
    processing: HashMap<Vec<u8>, HashMap<u16, Signature<E>>>,
    threshold: u16,
    threshold_counter: Box<dyn ThresholdCounter>,
}

impl<E: Curve> Signer<E> {
    pub fn new(keypair: Keypair<E>, threshold_counter: Box<dyn ThresholdCounter>) -> Self {
        let peers = HashMap::new();
        let processing = HashMap::new();
        let threshold = 0;

        Self {
            keypair,
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
        Signature::generate::<H>(seed, message, &self.keypair)
    }

    pub fn update<H: Digest + Clone>(
        &mut self,
        signature: Signature<E>,
        peer: PeerId,
    ) -> Option<Signature<E>> {
        let index = self.get_peer_index(&peer).expect("Unknown peer");

        let random_pub_key_bytes = signature
            .random_pub_key()
            .expect("Missing random public key")
            .to_bytes();

        let signatures = self
            .processing
            .entry(random_pub_key_bytes.clone())
            .or_default();

        signatures.insert(index, signature);

        if signatures.len() == self.threshold as usize {
            let signatures = self
                .processing
                .remove(&random_pub_key_bytes)
                .expect("Missing signatures");

            let indices: Vec<u16> = signatures.keys().copied().collect();
            let signatures: Vec<Signature<E>> = signatures.into_values().collect();

            return Some(Signature::aggregate::<H>(&indices, signatures));
        }

        None
    }

    fn get_peer_index(&self, peer: &PeerId) -> Option<u16> {
        self.peers.get(peer).copied()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use curv::elliptic::curves::Secp256k1;
    use libp2p::PeerId;
    use sha2::Sha256;

    use crate::crypto::dkg::classic::{
        config::ThresholdCounter, keypair::Keypair, signer::Signer, Signature,
    };

    const NUM_PEERS: u16 = 3;

    type E = Secp256k1;
    type H = Sha256;

    fn generate_peers(n: u16) -> HashMap<PeerId, u16> {
        (0..n)
            .map(|i| (PeerId::random(), i))
            .collect::<HashMap<_, _>>()
    }

    struct TestThresholdCounter;

    impl ThresholdCounter for TestThresholdCounter {
        fn call(&self, n: u16) -> u16 {
            (2 * n / 3) + 1
        }

        fn clone_box(&self) -> Box<dyn ThresholdCounter> {
            Box::new(TestThresholdCounter)
        }
    }

    #[test]
    fn create_current_items() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);

        let signer = Signer::new(keypair.clone(), threshold_counter);

        assert_eq!(signer.keypair, keypair);
        assert_eq!(signer.peers.len(), 0);
        assert_eq!(signer.processing.len(), 0);
        assert_eq!(signer.threshold, 0);
    }

    #[test]
    fn add_peers_updates_threshold() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let mut signer = Signer::new(keypair, threshold_counter);
        let peers = generate_peers(NUM_PEERS);
        let expected_threshold = (2 * NUM_PEERS / 3) + 1;

        signer.add_peers(peers.clone());

        assert_eq!(signer.peers.len(), NUM_PEERS as usize);
        assert_eq!(signer.threshold, expected_threshold);
        for (peer_id, idx) in peers {
            assert_eq!(signer.get_peer_index(&peer_id), Some(idx));
        }
    }

    #[test]
    fn sign_generates_valid_signature() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let signer = Signer::new(keypair, threshold_counter);
        let seed = b"test_seed";
        let message = b"test_message";

        let signature = signer.sign::<H>(seed, message);
        let is_valid = signature.validate();

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn update_returns_none_when_threshold_not_met() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let mut signer = Signer::new(keypair.clone(), threshold_counter);
        let peers = generate_peers(NUM_PEERS);
        let peer_id = *peers.keys().next().unwrap();
        signer.add_peers(peers);
        let seed = b"test_seed";
        let message = b"test_message";
        let signature = signer.sign::<H>(seed, message);

        let result = signer.update::<H>(signature, peer_id);

        assert!(result.is_none());
        assert_eq!(signer.processing.len(), 1);
    }

    #[test]
    fn update_aggregates_signatures_when_threshold_met() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let mut signer = Signer::new(keypair.clone(), threshold_counter);
        let peers = generate_peers(NUM_PEERS);
        let peer_ids: Vec<PeerId> = peers.keys().cloned().collect();
        signer.add_peers(peers);

        let seed = b"test_seed";
        let message = b"test_message";
        let signature = Signature::generate::<H>(seed, message, &keypair);

        (0..NUM_PEERS - 1).for_each(|i| {
            let peer_id = peer_ids[i as usize];
            let signature_clone = signature.clone();
            signer.update::<H>(signature_clone, peer_id);
        });

        let result = signer.update::<H>(signature, peer_ids[NUM_PEERS as usize - 1]);

        assert!(result.is_some());
        assert_eq!(signer.processing.len(), 0);
    }

    #[test]
    fn get_peer_index_returns_none_for_unknown_peer() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let signer = Signer::new(keypair, threshold_counter);
        let unknown_peer = PeerId::random();

        let result = signer.get_peer_index(&unknown_peer);

        assert_eq!(result, None);
    }

    #[test]
    fn get_peer_index_returns_index_for_known_peer() {
        let keypair = Keypair::<E>::random();
        let threshold_counter = Box::new(TestThresholdCounter);
        let mut signer = Signer::new(keypair, threshold_counter);
        let peers = generate_peers(NUM_PEERS);
        let (peer_id, expected_index) = peers.iter().next().map(|(k, v)| (*k, *v)).unwrap();
        signer.add_peers(peers);

        let result = signer.get_peer_index(&peer_id);

        assert_eq!(result, Some(expected_index));
    }
}
