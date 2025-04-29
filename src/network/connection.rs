use crate::{
    mocks::MockError,
    network::record::{Record, RecordKey},
    proposal::Proposal,
};

#[mockall::automock(type Error = MockError;)]
#[async_trait::async_trait]
pub trait Connection: Send + Sync + 'static {
    type Error: std::error::Error;

    async fn send_proposal<P: Proposal>(&self, proposal: P) -> Result<(), Self::Error>;
    async fn query_record<P: Proposal>(
        &self,
        key: &RecordKey,
    ) -> Result<Option<Record<P>>, Self::Error>;
}
