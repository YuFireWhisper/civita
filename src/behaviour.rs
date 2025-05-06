use crate::{
    network::transport::protocols::kad,
    traits::{byteable::MockByteable, Byteable},
};

#[mockall::automock(type Error = crate::mocks::MockError; type Proposal = MockByteable; type Resident = MockByteable;)]
#[async_trait::async_trait]
pub trait Behaviour: Send + Sync + 'static {
    type Error: std::error::Error;
    type Proposal: Byteable;
    type Resident: Byteable + Send + Sync;

    async fn validate(
        proposal: Vec<u8>,
        current_payloads: &mut [(kad::Key, kad::Payload)],
    ) -> Result<bool, Self::Error>;
    async fn list_impacted_kad_keys(
        proposal: &Self::Proposal,
    ) -> Result<Vec<kad::Key>, Self::Error>;
    fn get_weight(resident: Self::Resident) -> Result<u32, Self::Error>;
}
