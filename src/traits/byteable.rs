use crate::mocks::MockError;

#[mockall::automock(type Error = MockError;)]
pub trait Byteable {
    type Error: std::error::Error + std::fmt::Debug;

    #[mockall::concretize]
    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error>;

    #[mockall::concretize]
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
