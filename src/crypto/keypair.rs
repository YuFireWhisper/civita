use bincode::{Decode, Encode};

mod secp256k1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("{0}")]
    Secpk1(#[from] secp256k1::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(Eq, PartialEq)]
pub enum SecretKey {
    Secp256k1(secp256k1::SecretKey),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(Eq, PartialEq)]
pub enum PublicKey {
    Secp256k1(secp256k1::PublicKey),
}

impl SecretKey {
    pub fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            SecretKey::Secp256k1(sk) => sk.decrypt(msg).map_err(Error::from),
        }
    }
}

impl PublicKey {
    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            PublicKey::Secp256k1(pk) => pk.encrypt(msg).map_err(Error::from),
        }
    }
}

pub fn generate_secp256k1() -> (SecretKey, PublicKey) {
    let (sk, pk) = secp256k1::generate_keypair();
    (SecretKey::Secp256k1(sk), PublicKey::Secp256k1(pk))
}
