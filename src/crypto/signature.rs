use libp2p::identity::Keypair;

pub struct Signature {
    keypair: Keypair,
}

impl Signature {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
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
}
