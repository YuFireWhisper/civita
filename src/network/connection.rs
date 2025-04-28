use crate::proposal::Proposal;

#[async_trait::async_trait]
pub trait Connection {
    type Error: std::error::Error;

    async fn send_proposal<P: Proposal>(&self, proposal: P) -> Result<(), Box<Self::Error>>;
}
