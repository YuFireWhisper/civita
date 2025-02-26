use libp2p::identity::{Keypair, PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("Signature error: {0}")]
    Signature(String),
    #[error("Bytes too short")]
    BytesTooShort,
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

    pub fn random_value(&self, seed: u64) -> VrfResult<f64> {
        let input = seed.to_le_bytes();
        let (output, _) = self.prove(&input)?;
        let value = Self::u64_from_bytes(&output)?;
        Ok(Self::normalize(value))
    }

    fn u64_from_bytes(bytes: &[u8]) -> VrfResult<u64> {
        if bytes.len() < 8 {
            return Err(VrfError::BytesTooShort);
        }
        Ok(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
    }

    fn normalize(value: u64) -> f64 {
        value as f64 / u64::MAX as f64
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

    #[test]
    fn test_random_value() {
        let keypair = Keypair::generate_ed25519();
        let vrf = Vrf::new(keypair);

        const ITERATIONS: u64 = 1000;
        let mut previous_value = None;
        let mut values = Vec::new();

        for seed in 0..ITERATIONS {
            let result = vrf.random_value(seed).unwrap();

            assert!(
                (0.0..=1.0).contains(&result),
                "Value {} for seed {} should be between 0.0 and 1.0",
                result,
                seed
            );

            assert!(
                result.is_finite(),
                "Result should be finite for seed {}",
                seed
            );
            assert!(
                !result.is_nan(),
                "Result should not be NaN for seed {}",
                seed
            );

            values.push(result);

            if let Some(prev) = previous_value {
                assert_ne!(
                    result,
                    prev,
                    "Values should differ between seeds {} and {}",
                    seed - 1,
                    seed
                );
            }
            previous_value = Some(result);

            let result_again = vrf.random_value(seed).unwrap();
            assert_eq!(
                result, result_again,
                "Same seed {} should produce same value",
                seed
            );
        }

        let mean = values.iter().sum::<f64>() / ITERATIONS as f64;
        assert!(
            mean > 0.3 && mean < 0.7,
            "Mean value {} should be roughly centered (0.3-0.7)",
            mean
        );
    }
}
