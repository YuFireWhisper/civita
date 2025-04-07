use std::{future::Future, sync::Arc};

use libp2p::gossipsub::MessageId;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use crate::network::transport::{
    self,
    libp2p_transport::protocols::gossipsub::{Message, Payload},
    Transport,
};

use super::proof::Proof;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(String),
    #[error("Failed to get message ID")]
    MessageId,
}

impl From<transport::Error> for Error {
    fn from(err: transport::Error) -> Self {
        Error::Transport(err.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

pub trait MessagerEngine: Send + Sync {
    fn subscribe(&self) -> impl Future<Output = Result<Receiver<Message>>>;
    fn send_vrf_request(&self) -> impl Future<Output = Result<MessageId>>;
    fn send_vrf_proof(
        &self,
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    ) -> impl Future<Output = Result<MessageId>>;
    fn send_vrf_consensus(
        &self,
        message_id: MessageId,
        random: [u8; 32],
    ) -> impl Future<Output = Result<MessageId>>;
    fn send_vrf_failure(&self, message_id: MessageId) -> impl Future<Output = Result<MessageId>>;
}

pub struct Messager<T: Transport> {
    transport: Arc<T>,
    topic: String,
}

impl<T: Transport> Messager<T> {
    pub fn new(transport: Arc<T>, topic: String) -> Self {
        Self { transport, topic }
    }

    async fn send(&self, payload: Payload) -> Result<MessageId> {
        let message_id = self.transport.publish(&self.topic, payload).await?;
        Ok(message_id)
    }
}

impl<T: Transport> MessagerEngine for Messager<T> {
    async fn subscribe(&self) -> Result<Receiver<Message>> {
        self.transport
            .listen_on_topic(&self.topic)
            .await
            .map_err(Error::from)
    }

    async fn send_vrf_request(&self) -> Result<MessageId> {
        self.send(Payload::VrfRequest).await
    }

    async fn send_vrf_proof(
        &self,
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    ) -> Result<MessageId> {
        let payload = Payload::create_vrf_proof(message_id, public_key, vrf_proof.proof().to_vec());
        self.send(payload).await
    }

    async fn send_vrf_consensus(
        &self,
        message_id: MessageId,
        random: [u8; 32],
    ) -> Result<MessageId> {
        let payload = Payload::create_vrf_consensus(message_id, random);
        self.send(payload).await
    }

    async fn send_vrf_failure(&self, message_id: MessageId) -> Result<MessageId> {
        self.send(Payload::VrfProcessFailure(message_id)).await
    }
}

#[cfg(test)]
mod tests {
    #[ignore]
    #[tokio::test]
    async fn test_subscribe() {
        todo!("We will implement this after we define the Transport trait");
    }

    #[ignore]
    #[tokio::test]
    async fn test_send_vrf_request_success() {
        todo!("We will implement this after we define the Transport trait");
    }

    #[ignore]
    #[tokio::test]
    async fn test_send_vrf_request_no_message_id() {
        todo!("We will implement this after we define the Transport trait");
    }

    #[ignore]
    #[tokio::test]
    async fn test_send_vrf_proof_success() {
        todo!("We will implement this after we define the Transport trait");
    }

    #[ignore]
    #[tokio::test]
    async fn test_send_vrf_consensus_success() {
        todo!("We will implement this after we define the Transport trait");
    }

    #[ignore]
    #[tokio::test]
    async fn test_send_vrf_failure_success() {
        todo!("We will implement this after we define the Transport trait");
    }
}
