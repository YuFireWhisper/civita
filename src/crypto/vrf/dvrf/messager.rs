use std::{future::Future, sync::Arc};

use libp2p::gossipsub::MessageId;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use crate::network::transport::{
    self,
    libp2p_transport::message::{
        gossipsub::{self, Payload},
        Message,
    },
    SubscriptionFilter, Transport,
};

use super::proof::Proof;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),
    #[error("Failed to get message ID")]
    MessageId,
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

pub struct Messager {
    transport: Arc<dyn Transport>,
    topic: String,
}

impl Messager {
    pub fn new(transport: Arc<dyn Transport>, topic: String) -> Self {
        Self { transport, topic }
    }

    async fn send(&self, payload: Payload) -> Result<MessageId> {
        let msg = self.create_gossipsub_message(payload);
        let message_id = self.transport.send(msg).await?.ok_or(Error::MessageId)?;
        Ok(message_id)
    }

    fn create_gossipsub_message(&self, payload: Payload) -> Message {
        let gossip_msg = gossipsub::Message::new(&self.topic, payload);
        Message::Gossipsub(gossip_msg)
    }
}

impl MessagerEngine for Messager {
    async fn subscribe(&self) -> Result<Receiver<Message>> {
        let filter = SubscriptionFilter::Topic(self.topic.clone());
        self.transport.subscribe(filter).await.map_err(Error::from)
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
    use std::sync::Arc;

    use crate::network::transport::libp2p_transport::{
        test_transport::{TestTransport, TEST_TOPIC},
        Libp2pTransport,
    };

    use super::Messager;

    async fn create_arc_test_transport() -> Arc<Libp2pTransport> {
        Arc::new(TestTransport::new().await.unwrap().p2p)
    }

    #[tokio::test]
    async fn test_new() {
        let transport = create_arc_test_transport().await;

        let messager = Messager::new(transport, TEST_TOPIC.to_string());

        assert_eq!(messager.topic, TEST_TOPIC);
    }

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
