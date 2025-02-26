use libp2p::identity::Keypair;

pub struct Vrf {
    keypair: Keypair,
}

impl Vrf {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
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
}
