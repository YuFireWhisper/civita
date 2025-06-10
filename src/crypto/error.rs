#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Serialization(String),
}

impl From<ark_serialize::SerializationError> for Error {
    fn from(e: ark_serialize::SerializationError) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(e: bincode::error::EncodeError) -> Self {
        Error::Serialization(e.to_string())
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(e: bincode::error::DecodeError) -> Self {
        Error::Serialization(e.to_string())
    }
}
