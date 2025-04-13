pub struct Ecies {
    secret_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl Ecies {
    pub fn generate() -> Self {
        let (sk, pk) = ecies::utils::generate_keypair();
        let secret_key = Some(sk.serialize().to_vec());
        let public_key = Some(pk.serialize_compressed().to_vec());

        Self {
            secret_key,
            public_key,
        }
    }

    pub fn secret_key(&self) -> Option<&Vec<u8>> {
        self.secret_key.as_ref()
    }

    pub fn public_key(&self) -> Option<&Vec<u8>> {
        self.public_key.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair::ecies::Ecies;

    #[test]
    fn generate_keypair_is_not_none() {
        let ecies = Ecies::generate();
        assert!(ecies.secret_key().is_some());
        assert!(ecies.public_key().is_some());
    }
}
