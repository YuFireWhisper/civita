use std::sync::Arc;

use ark_bls12_381::Fr;
use ark_std::{rand, UniformRand};
use libp2p::PeerId;

use crate::network::transport::Transport;

use super::Dkg;

pub struct DkgClassic {
    transport: Arc<Transport>,
    peer_ids: Vec<PeerId>,
    threshold: usize,
    poly: Vec<Fr>,
}

impl DkgClassic {
    fn calculate_threshold(threshold_ratio: usize, total_residents: usize) -> usize {
        (total_residents * threshold_ratio) / 100
    }

    fn generate_poly(threshold: usize) -> Vec<Fr> {
        let mut rng = rand::rngs::OsRng;
        let mut coefficients = Vec::with_capacity(threshold);

        for _ in 0..threshold {
            let coeff = Fr::rand(&mut rng);
            coefficients.push(coeff);
        }

        coefficients
    }
}

impl Dkg for DkgClassic {
    fn new(transport: Arc<Transport>, peer_ids: Vec<PeerId>, threshold_ratio: usize) -> Self {
        let threshold = Self::calculate_threshold(threshold_ratio, peer_ids.len());
        let poly = Self::generate_poly(threshold);

        DkgClassic {
            transport,
            peer_ids,
            threshold,
            poly,
        }
    }

    fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        todo!()
    }

    fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::network::transport::test_transport::TestTransport;

    use super::*;

    #[tokio::test]
    async fn test_new() {
        let node = TestTransport::new().await.unwrap();
        let transport = Arc::new(node.p2p);
        let peer_ids = vec![PeerId::random(), PeerId::random(), PeerId::random()];
        let threshold_ratio = 67;

        let dkg = DkgClassic::new(transport, peer_ids, threshold_ratio);

        assert_eq!(dkg.peer_ids.len(), 3);
        assert_eq!(dkg.threshold, 2);
        assert_eq!(dkg.poly.len(), 2);
    }
}
