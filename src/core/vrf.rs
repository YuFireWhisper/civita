use libp2p::identity::{Keypair, PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("Signature error: {0}")]
    Signature(String),
}

type VrfResult<T> = Result<T, VrfError>;

pub struct Vrf {
    keypair: Keypair,
}

impl Vrf {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    pub fn prove(&self, input: &[u8]) -> VrfResult<(Vec<u8>, Vec<u8>)> {
        let proof = self.generate_signature(input)?;
        let output = self.compute_hash(&proof);
        Ok((output, proof.to_vec()))
    }

    fn generate_signature(&self, input: &[u8]) -> VrfResult<Vec<u8>> {
        match self.keypair.sign(input) {
            Ok(sig) => Ok(sig.to_vec()),
            Err(e) => Err(VrfError::Signature(e.to_string())),
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
    use libp2p::identity::Keypair;

    use super::Vrf;

    #[test]
    fn test_new() {
        let keypair = Keypair::generate_ed25519();

        let vrf = Vrf::new(keypair.clone());

        assert_eq!(
            vrf.keypair.public(),
            keypair.public(),
            "Vrf should store the keypair"
        );
    }

    #[test]
    fn test_compute() {
        let keypair = Keypair::generate_ed25519();
        let vrf = Vrf::new(keypair);

        let input = b"input";
        let (output, signature) = vrf.prove(input).unwrap();

        assert_eq!(output.len(), 32, "Vrf output should be 32 bytes long");
        assert_eq!(signature.len(), 64, "Vrf signature should be 64 bytes long");
    }

    #[test]
    fn test_verify_valid() {
        let keypair = Keypair::generate_ed25519();
        let vrf = Vrf::new(keypair.clone());

        let input = b"input";
        let (output, proof) = vrf.prove(input).unwrap();

        let is_valid = Vrf::verify(&keypair.public(), input, &output, &proof).unwrap();

        assert!(is_valid, "Vrf should verify the output and proof");
    }

    #[test]
    fn test_verify_invalid() {
        let keypair = Keypair::generate_ed25519();
        let vrf = Vrf::new(keypair.clone());

        let input = b"input";
        let (output, _) = vrf.prove(input).unwrap();

        let is_valid = Vrf::verify(&keypair.public(), input, &output, &[0; 64]).unwrap();

        assert!(!is_valid, "Vrf should not verify the output and proof");
    }
}
