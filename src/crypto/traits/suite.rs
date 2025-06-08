use crate::crypto::traits::{public_key::PublicKey, secret_key::SecretKey};

pub trait Suite {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey>;
    type PublicKey: PublicKey;
}
