use std::{future::Future, pin::Pin, sync::Arc};

use libp2p::gossipsub::MessageId;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use crate::network::{
    message::{gossipsub, Message, Payload},
    transport::{self, libp2p_transport::Libp2pTransport, SubscriptionFilter},
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

pub trait MessagerEngine {
    fn subscribe(&self) -> Pin<Box<dyn Future<Output = Receiver<Message>> + Send + '_>>;
    fn send_vrf_request(&self) -> Pin<Box<dyn Future<Output = Result<MessageId>> + Send + '_>>;
    fn send_vrf_proof(
        &self,
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>>;
    fn send_vrf_consensus(
        &self,
        message_id: MessageId,
        random: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>>;
    fn send_vrf_failure(
        &self,
        message_id: MessageId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>>;
}

pub struct Messager {
    transport: Arc<Libp2pTransport>,
    topic: String,
}

impl Messager {
    pub fn new(transport: Arc<Libp2pTransport>, topic: String) -> Self {
        Self { transport, topic }
    }

    async fn send(&self, payload: Payload) -> Result<Option<MessageId>> {
        let msg = self.create_message(payload);
        let message_id = self.transport.send(msg).await?;
        Ok(message_id)
    }

    fn create_message(&self, payload: Payload) -> Message {
        let gossip_msg = gossipsub::Message::new(&self.topic, payload);
        Message::Gossipsub(gossip_msg)
    }
}

impl MessagerEngine for Messager {
    fn subscribe(&self) -> Pin<Box<dyn Future<Output = Receiver<Message>> + Send + '_>> {
        Box::pin(async move {
            let filter = SubscriptionFilter::Topic(self.topic.clone());
            self.transport.subscribe(filter).await
        })
    }

    fn send_vrf_request(&self) -> Pin<Box<dyn Future<Output = Result<MessageId>> + Send + '_>> {
        Box::pin(async move {
            let payload = Payload::create_vrf_request();
            self.send(payload).await?.ok_or(Error::MessageId)
        })
    }

    fn send_vrf_proof(
        &self,
        message_id: MessageId,
        public_key: Vec<u8>,
        vrf_proof: Proof,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>> {
        Box::pin(async move {
            let payload = Payload::create_vrf_proof(message_id, public_key, vrf_proof);
            self.send(payload).await
        })
    }

    fn send_vrf_consensus(
        &self,
        message_id: MessageId,
        random: [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>> {
        Box::pin(async move {
            let payload = Payload::create_vrf_consensus(message_id, random);
            self.send(payload).await
        })
    }

    fn send_vrf_failure(
        &self,
        message_id: MessageId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send + '_>> {
        Box::pin(async move {
            let payload = Payload::create_vrf_failure(message_id);
            self.send(payload).await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::network::transport::libp2p_transport::{test_transport::{TestTransport, TEST_TOPIC}, Libp2pTransport};

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
