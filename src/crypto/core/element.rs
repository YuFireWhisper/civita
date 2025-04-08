use std::iter::Sum;

pub trait Element: Sum {
    fn random() -> Self;
}

pub trait Secret: Element {
    type PublicKey: Public<Secret = Self>;

    fn to_public(&self) -> Self::PublicKey;
    fn to_vec(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}

pub trait Public: Element + Clone {
    type Secret: Secret<PublicKey = Self>;

    fn to_vec(&self) -> Vec<u8>;
    fn verify_secret(&self, secret: &Self::Secret) -> bool;
    fn from_bytes(bytes: &[u8]) -> Self;
}
