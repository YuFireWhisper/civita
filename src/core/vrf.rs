use libp2p::identity::Keypair;
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

    pub fn compute(&self, input: &[u8]) -> VrfResult<(Vec<u8>, Vec<u8>)> {
        let signature = self.generate_signature(input)?;
        let output = self.compute_hash(&signature);
        Ok((output, signature.to_vec()))
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
        let (output, signature) = vrf.compute(input).unwrap();

        assert_eq!(output.len(), 32, "Vrf output should be 32 bytes long");
        assert_eq!(signature.len(), 64, "Vrf signature should be 64 bytes long");
    }
}
