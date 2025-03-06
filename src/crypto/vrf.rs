use std::sync::Arc;

use libp2p::identity::{Keypair, PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("Bytes too short")]
    BytesTooShort,
}

type VrfResult<T> = Result<T, Error>;

pub struct VrfProof {
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct Vrf {
    keypair: Arc<Keypair>,
}

impl Vrf {
    pub fn new(keypair: Arc<Keypair>) -> Self {
        Self { keypair }
    }

    pub fn prove(&self, input: &[u8]) -> VrfResult<VrfProof> {
        let proof = self.generate_signature(input)?;
        let output = self.compute_hash(&proof);
        Ok(VrfProof { output, proof })
    }

    fn generate_signature(&self, input: &[u8]) -> VrfResult<Vec<u8>> {
        match self.keypair.sign(input) {
            Ok(sig) => Ok(sig.to_vec()),
            Err(e) => Err(Error::Signature(e.to_string())),
        }
    }

    fn compute_hash(&self, input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().to_vec()
    }

    pub fn verify(
        public_key: &PublicKey,
        input: &[u8],
        output: &[u8],
        proof: &[u8],
    ) -> VrfResult<bool> {
        let is_signature_valid = public_key.verify(input, proof);
        if !is_signature_valid {
            return Ok(false);
        }

        let expected_output = Self::compute_expected_output(proof);
        Ok(expected_output == output)
    }

    fn compute_expected_output(proof: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(proof);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libp2p::identity::Keypair;

    use super::Vrf;

    const TEST_INPUT: &[u8] = b"input";

    fn generate_keypair() -> Arc<Keypair> {
        Arc::new(Keypair::generate_ed25519())
    }

    #[test]
    fn test_new() {
        let keypair = generate_keypair();
        let vrf = Vrf::new(keypair.clone());
        assert_eq!(
            vrf.keypair.public(),
            keypair.public(),
            "Vrf should store the keypair"
        );
    }

    #[test]
    fn test_prove() {
        let keypair = generate_keypair();
        let vrf = Vrf::new(keypair);

        let vrf_proof = vrf.prove(TEST_INPUT);

        assert!(vrf_proof.is_ok(), "Vrf should prove the input");
    }

    #[test]
    fn test_verify_valid() {
        let keypair = generate_keypair();
        let vrf = Vrf::new(keypair.clone());
        let vrf_proof = vrf.prove(TEST_INPUT).unwrap();
        let is_valid = Vrf::verify(
            &keypair.public(),
            TEST_INPUT,
            &vrf_proof.output,
            &vrf_proof.proof,
        )
        .unwrap();
        assert!(is_valid, "Vrf should verify the output and proof");
    }

    #[test]
    fn test_verify_invalid() {
        let keypair = generate_keypair();
        let vrf = Vrf::new(keypair.clone());
        let vrf_proof = vrf.prove(TEST_INPUT).unwrap();
        let is_valid =
            Vrf::verify(&keypair.public(), TEST_INPUT, &[0; 32], &vrf_proof.proof).unwrap();
        assert!(!is_valid, "Vrf should not verify invalid output");
    }
}
