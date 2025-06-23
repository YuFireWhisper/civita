use crate::traits::serializable;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Serializable(#[from] serializable::Error),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Vrf verification failed")]
    VrfVerificationFailed,
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Error::Serializable(serializable::Error(e.to_string()))
    }
}
