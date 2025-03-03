use libp2p::identity::Keypair;

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
}

#[cfg(test)]
mod tests {
    use libp2p::identity::Keypair;

    use super::Signature;

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
}
