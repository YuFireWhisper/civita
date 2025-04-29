use crate::{
    mocks::MockError,
    network::{connection::Connection, record::Record},
    traits::Byteable,
};

#[mockall::automock(type Error = MockError; type CustomValue = Vec<u8>;)]
#[async_trait::async_trait]
pub trait Proposal: Byteable + Sized + Send + Sync + 'static {
    type Error: std::error::Error;
    type CustomValue: Byteable;

    async fn validate<C: Connection>(
        &self,
        connection: &C,
    ) -> Result<bool, <Self as Proposal>::Error>;
    async fn to_record<C: Connection>(
        &self,
        connection: &C,
    ) -> Result<Record<Self>, <Self as Proposal>::Error>;
}

impl Byteable for MockProposal {
    type Error = MockError;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(vec![])
    }

    fn from_bytes<B: AsRef<[u8]>>(_bytes: B) -> Result<Self, Self::Error> {
        Ok(MockProposal::default())
    }
}

impl Clone for MockProposal {
    fn clone(&self) -> Self {
        MockProposal::default()
    }
}

impl Byteable for Vec<u8> {
    type Error = MockError;

    fn to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.clone())
    }

    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Self::Error> {
        Ok(bytes.as_ref().to_vec())
    }
}
