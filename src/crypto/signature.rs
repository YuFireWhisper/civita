use libp2p::identity::Keypair;

#[derive(Debug)]
pub struct Signature {
    keypair: Keypair,
}

impl Signature {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self.keypair
            .sign(input)
            .map(|sig| sig.to_vec())
            .map_err(|e| e.to_string())
    }

    pub fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        self.keypair.public().verify(input, signature)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;

    use super::Signature;

    const TEST_INPUT: &[u8] = b"input";

    #[test]
    fn test_new() {
        let keypair = Keypair::generate_ed25519();

        let signature = Signature::new(keypair.clone());

        assert_eq!(
            signature.keypair.public(),
            keypair.public(),
            "Signature should store the keypair"
        );
    }

    #[test]
    fn test_sign() {
        let keypair = Keypair::generate_ed25519();
        let signature = Signature::new(keypair.clone());

        let input = b"input";
        let signature_bytes = signature.sign(input).unwrap();

        assert!(
            keypair.public().verify(input, &signature_bytes),
            "Signature should be valid"
        );
    }

    #[test]
    fn test_verify_valid() {
        let keypair = Keypair::generate_ed25519();
        let signature = Signature::new(keypair.clone());
        let signature_bytes = signature.sign(TEST_INPUT).unwrap();

        let is_valid = signature.verify(TEST_INPUT, &signature_bytes);

        assert!(is_valid, "Signature should be valid");
    }
}
