pub trait Data {
    fn validate(&self, message: &[u8], key: &[u8]) -> bool;
}

pub trait Scheme {
    type Error;
    type Output: Data;
    type Keypair;

    fn sign(
        seed: &[u8],
        message: &[u8],
        keypair: &Self::Keypair,
    ) -> Result<Self::Output, Self::Error>;
}
