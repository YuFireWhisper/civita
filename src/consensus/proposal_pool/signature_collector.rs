use std::collections::HashMap;

use crate::{
    constants::HashArray,
    crypto::keypair::{PublicKey, ResidentSignature, VrfProof},
};

#[derive(Debug)]
pub struct SignatureCollector {
    final_hash: HashArray,
    signatures: HashMap<PublicKey, (VrfProof, ResidentSignature)>,
}

impl SignatureCollector {
    pub fn new(hash: HashArray) -> Self {
        Self {
            final_hash: hash,
            signatures: HashMap::new(),
        }
    }

    pub fn add_signature(
        &mut self,
        public_key: PublicKey,
        proof: VrfProof,
        signature: ResidentSignature,
    ) {
        if !public_key.verify_signature(self.final_hash, &signature) {
            return;
        }

        self.signatures.insert(public_key, (proof, signature));
    }

    pub fn get_signatures(&mut self) -> HashMap<PublicKey, (VrfProof, ResidentSignature)> {
        std::mem::take(&mut self.signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::{self, KeyType};

    const TEST_HASH: HashArray = [1u8; 32];
    const INVALID_HASH: HashArray = [2u8; 32];

    fn setup_valid_signature() -> (PublicKey, VrfProof, ResidentSignature) {
        let (sk, pk) = keypair::generate_keypair(KeyType::Secp256k1);
        let proof = sk.prove("test message").unwrap();
        let signature = sk.sign(TEST_HASH).unwrap();
        (pk, proof, signature)
    }

    fn setup_invalid_signature() -> (PublicKey, VrfProof, ResidentSignature) {
        let (sk, pk) = keypair::generate_keypair(KeyType::Secp256k1);
        let proof = sk.prove("test message").unwrap();
        // Create signature with different hash to make it invalid
        let signature = sk.sign(INVALID_HASH).unwrap();
        (pk, proof, signature)
    }

    #[test]
    fn new_collector_creation() {
        let collector = SignatureCollector::new(TEST_HASH);

        assert_eq!(collector.final_hash, TEST_HASH);
        assert!(collector.signatures.is_empty());
    }

    #[test]
    fn add_valid_signature() {
        let mut collector = SignatureCollector::new(TEST_HASH);
        let (pk, proof, signature) = setup_valid_signature();

        collector.add_signature(pk.clone(), proof.clone(), signature.clone());

        assert_eq!(collector.signatures.len(), 1);
        assert!(collector.signatures.contains_key(&pk));
        let stored = collector.signatures.get(&pk).unwrap();
        assert_eq!(stored.0, proof);
        assert_eq!(stored.1, signature);
    }

    #[test]
    fn add_invalid_signature_rejected() {
        let mut collector = SignatureCollector::new(TEST_HASH);
        let (pk, proof, signature) = setup_invalid_signature();

        collector.add_signature(pk.clone(), proof, signature);

        assert!(collector.signatures.is_empty());
        assert!(!collector.signatures.contains_key(&pk));
    }

    #[test]
    fn add_multiple_valid_signatures() {
        let mut collector = SignatureCollector::new(TEST_HASH);

        // Add first signature
        let (pk1, proof1, signature1) = setup_valid_signature();
        collector.add_signature(pk1.clone(), proof1.clone(), signature1.clone());

        // Add second signature
        let (pk2, proof2, signature2) = setup_valid_signature();
        collector.add_signature(pk2.clone(), proof2.clone(), signature2.clone());

        assert_eq!(collector.signatures.len(), 2);
        assert!(collector.signatures.contains_key(&pk1));
        assert!(collector.signatures.contains_key(&pk2));
    }

    #[test]
    fn add_signature_overwrites_existing() {
        let mut collector = SignatureCollector::new(TEST_HASH);
        let (sk, pk) = keypair::generate_keypair(KeyType::Secp256k1);

        // Add first signature
        let proof1 = sk.prove("first message").unwrap();
        let signature1 = sk.sign(TEST_HASH).unwrap();
        collector.add_signature(pk.clone(), proof1, signature1);

        // Add second signature with same key
        let proof2 = sk.prove("second message").unwrap();
        let signature2 = sk.sign(TEST_HASH).unwrap();
        collector.add_signature(pk.clone(), proof2.clone(), signature2.clone());

        assert_eq!(collector.signatures.len(), 1);
        let stored = collector.signatures.get(&pk).unwrap();
        assert_eq!(stored.0, proof2);
        assert_eq!(stored.1, signature2);
    }

    #[test]
    fn mixed_valid_invalid_signatures() {
        let mut collector = SignatureCollector::new(TEST_HASH);

        // Add valid signature
        let (valid_pk, valid_proof, valid_signature) = setup_valid_signature();
        collector.add_signature(
            valid_pk.clone(),
            valid_proof.clone(),
            valid_signature.clone(),
        );

        // Add invalid signature
        let (invalid_pk, invalid_proof, invalid_signature) = setup_invalid_signature();
        collector.add_signature(invalid_pk.clone(), invalid_proof, invalid_signature);

        assert_eq!(collector.signatures.len(), 1);
        assert!(collector.signatures.contains_key(&valid_pk));
        assert!(!collector.signatures.contains_key(&invalid_pk));
    }

    #[test]
    fn get_signatures_returns_all() {
        let mut collector = SignatureCollector::new(TEST_HASH);

        // Add multiple signatures
        let (pk1, proof1, signature1) = setup_valid_signature();
        let (pk2, proof2, signature2) = setup_valid_signature();
        collector.add_signature(pk1.clone(), proof1.clone(), signature1.clone());
        collector.add_signature(pk2.clone(), proof2.clone(), signature2.clone());

        let signatures = collector.get_signatures();

        assert_eq!(signatures.len(), 2);
        assert!(signatures.contains_key(&pk1));
        assert!(signatures.contains_key(&pk2));

        let stored1 = signatures.get(&pk1).unwrap();
        assert_eq!(stored1.0, proof1);
        assert_eq!(stored1.1, signature1);

        let stored2 = signatures.get(&pk2).unwrap();
        assert_eq!(stored2.0, proof2);
        assert_eq!(stored2.1, signature2);
    }

    #[test]
    fn get_signatures_empties_collector() {
        let mut collector = SignatureCollector::new(TEST_HASH);
        let (pk, proof, signature) = setup_valid_signature();
        collector.add_signature(pk, proof, signature);

        assert_eq!(collector.signatures.len(), 1);

        let _signatures = collector.get_signatures();

        // Collector should be empty after get_signatures
        assert!(collector.signatures.is_empty());
    }

    #[test]
    fn get_signatures_empty_collector() {
        let mut collector = SignatureCollector::new(TEST_HASH);

        let signatures = collector.get_signatures();

        assert!(signatures.is_empty());
    }

    #[test]
    fn get_signatures_multiple_calls() {
        let mut collector = SignatureCollector::new(TEST_HASH);
        let (pk, proof, signature) = setup_valid_signature();
        collector.add_signature(pk, proof, signature);

        // First call returns signatures
        let signatures1 = collector.get_signatures();
        assert_eq!(signatures1.len(), 1);

        // Second call returns empty map
        let signatures2 = collector.get_signatures();
        assert!(signatures2.is_empty());
    }

    #[test]
    fn signature_verification_with_different_hash() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];

        let mut collector = SignatureCollector::new(hash1);
        let (sk, pk) = keypair::generate_keypair(KeyType::Secp256k1);
        let proof = sk.prove("test message").unwrap();

        // Create signature for hash2, but collector expects hash1
        let signature = sk.sign(hash2).unwrap();

        collector.add_signature(pk.clone(), proof, signature);

        assert!(collector.signatures.is_empty());
    }
}
