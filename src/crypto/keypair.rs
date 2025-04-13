use bincode::{Decode, Encode};

mod ecies;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("{0}")]
    Ecies(#[from] ecies::Error),
}

#[derive(Debug)]
#[derive(Encode, Decode)]
pub enum Keypair {
    Ecies(ecies::Ecies),
}

impl Keypair {
    pub fn generate_ecies() -> Self {
        Keypair::Ecies(ecies::Ecies::generate())
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Keypair::Ecies(ecies) => ecies.encrypt(msg).map_err(Error::from),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Keypair::Ecies(ecies) => ecies.decrypt(ciphertext).map_err(Error::from),
        }
    }

    pub fn secret_key(&self) -> Option<&[u8]> {
        match self {
            Keypair::Ecies(ecies) => ecies.secret_key(),
        }
    }

    pub fn public_key(&self) -> &[u8] {
        match self {
            Keypair::Ecies(ecies) => ecies.public_key(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::try_from(slice)
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        self.try_into()
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        bincode::decode_from_slice(slice, bincode::config::standard())
            .map_err(Error::from).map(|(keypair, _)| keypair)
    }
}

impl TryFrom<&Keypair> for Vec<u8> {
    type Error = Error;

    fn try_from(keypair: &Keypair) -> Result<Self> {
        bincode::encode_to_vec(keypair, bincode::config::standard()).map_err(Error::from)
    }
}
