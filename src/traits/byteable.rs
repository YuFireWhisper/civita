use crate::mocks::MockError;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),
}

#[mockall::automock(type Error = MockError;)]
pub trait Byteable {
    type Error: std::error::Error + std::fmt::Debug;

    #[mockall::concretize]
    fn to_vec(&self) -> Result<Vec<u8>, Self::Error>;

    #[mockall::concretize]
    fn from_slice<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl<T> Byteable for T
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Error = Error;

    fn to_vec(&self) -> Result<Vec<u8>, Self::Error> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map_err(Error::from)
    }

    fn from_slice<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        bincode::serde::decode_from_slice(bytes.as_ref(), bincode::config::standard())
            .map(|(value, _)| value)
            .map_err(Error::from)
    }
}
