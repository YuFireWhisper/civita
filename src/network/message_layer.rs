use std::sync::Arc;
use std::sync::PoisonError;

use crossbeam_channel::Receiver;
use libp2p::{
    gossipsub::MessageId,
    identity::{self, Keypair},
    PeerId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::transport;
use super::transport::P2PMessage;
use super::transport::Transport;

#[derive(Debug, Error)]
pub enum MessageLayerError {
    #[error("Failed to serialize message: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Failed to sign message: {0}")]
    Signing(#[from] identity::SigningError),
    #[error("Failed to publish message: {0}")]
    Publishing(#[from] transport::Error),
    #[error("Failed to lock mutex: {0}")]
    Mutex(String),
    #[error("Failed to receive message: {0}")]
    Receive(#[from] crossbeam_channel::RecvError),
}

impl<T> From<PoisonError<T>> for MessageLayerError {
    fn from(error: PoisonError<T>) -> Self {
        MessageLayerError::Mutex(error.to_string())
    }
}

type MessageLayerResult<T> = std::result::Result<T, MessageLayerError>;

pub struct MessageLayer<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    p2p: Transport,
    keypair: Keypair,
    handler: Arc<MessageHandler<T>>,
}

impl<T> MessageLayer<T>
where
    T: Serialize + for<'de> Deserialize<'de> + 'static,
{
    pub fn new(p2p: Transport, keypair: Keypair, handler: Arc<MessageHandler<T>>) -> Self {
        Self {
            p2p,
            keypair,
            handler,
        }
    }

    pub async fn send(&mut self, content: T, topic: &str) -> MessageLayerResult<()> {
        let timestamp = chrono::Utc::now().timestamp() as u64;

        let mut message = SentMessage {
            content,
            timestamp,
            signature: Vec::new(),
        };

        let serialized_message = serde_json::to_vec(&message)?;
        let signature = self.keypair.sign(&serialized_message)?;

        message.signature = signature.to_vec();

        let data = serde_json::to_vec(&message)?;

        self.p2p
            .publish(topic, data)
            .await
            .map_err(MessageLayerError::Publishing)?;

        Ok(())
    }

    pub async fn start(&mut self, sleep_duration: tokio::time::Duration) -> MessageLayerResult<()> {
        self.p2p.start_receive(sleep_duration).await;
        self.spawn_message_handler();
        Ok(())
    }

    fn spawn_message_handler(&self) {
        let message_receiver = self.p2p.message_receiver();
        let handler = self.handler.clone();

        tokio::spawn(async move {
            loop {
                let message = match Self::blocking_receive(message_receiver.clone()).await {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("Failed to receive message: {:?}", e);
                        continue;
                    }
                };

                if let Err(e) = Self::process_received_message(message, handler.clone()) {
                    eprintln!("Message processing failed: {:?}", e);
                }
            }
        });
    }

    async fn blocking_receive(
        receiver: Arc<Receiver<P2PMessage>>,
    ) -> MessageLayerResult<P2PMessage> {
        let recv_result = tokio::task::spawn_blocking(move || receiver.recv())
            .await
            .map_err(|e| MessageLayerError::Mutex(e.to_string()))?;
        recv_result.map_err(MessageLayerError::from)
    }

    fn process_received_message(
        message: P2PMessage,
        handler: Arc<MessageHandler<T>>,
    ) -> MessageLayerResult<()> {
        let received_message: ReceivedMessage<T> =
            message.try_into().map_err(MessageLayerError::from)?;
        handler(received_message);
        Ok(())
    }
}

type MessageHandler<T> = dyn Fn(ReceivedMessage<T>) + Send + Sync;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentMessage<T>
where
    T: Serialize,
{
    pub content: T,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage<T>
where
    T: Serialize,
{
    pub content: T,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
}

impl<T> TryFrom<P2PMessage> for ReceivedMessage<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_from(p2p_message: P2PMessage) -> Result<Self, Self::Error> {
        let sent_message: SentMessage<T> = serde_json::from_slice(&p2p_message.data)?;
        Ok(ReceivedMessage {
            content: sent_message.content,
            timestamp: p2p_message.timestamp,
            signature: sent_message.signature,
            message_id: p2p_message.message_id,
            source: p2p_message.source,
            topic: p2p_message.topic,
        })
    }
}

#[cfg(test)]
mod tests {
    use libp2p::futures::channel::oneshot;
    use tokio::time::timeout;

    use crate::network::transport::test_communication::{
        TestCommunication, TEST_TIMEOUT_DURATION, TEST_TOPIC,
    };

    use super::*;
    use std::{collections::HashMap, time::Duration};

    #[tokio::test]
    async fn test_new() {
        let communication = TestCommunication::new().await.unwrap();
        let handler = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});

        let message_layer = MessageLayer::new(
            communication.p2p.clone(TEST_TIMEOUT_DURATION).await,
            communication.keypair,
            handler,
        );

        assert_eq!(message_layer.p2p, communication.p2p);
    }

    #[tokio::test]
    async fn test_send() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        node1
            .establish_gossipsub_connection(&mut node2)
            .await
            .unwrap();

        let handler = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});
        let mut message_layer = MessageLayer::new(node1.p2p, node1.keypair, handler);

        let content = HashMap::new();

        let result = message_layer.send(content, TEST_TOPIC).await;

        assert!(result.is_ok(), "Failed to send message: {:?}", result);
    }

    #[tokio::test]
    async fn test_start() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        node1
            .establish_gossipsub_connection(&mut node2)
            .await
            .unwrap();

        let (tx, rx) = oneshot::channel::<ReceivedMessage<HashMap<String, String>>>();
        let tx = std::sync::Mutex::new(Some(tx));

        let handler = Arc::new(move |msg: ReceivedMessage<HashMap<String, String>>| {
            let mut tx_guard = tx.lock().unwrap();
            if let Some(tx) = tx_guard.take() {
                let _ = tx.send(msg);
            }
        });

        let mut message_layer2 = MessageLayer::new(node2.p2p, node2.keypair, handler);
        message_layer2
            .start(Duration::from_millis(100))
            .await
            .unwrap();

        let handler_noop = Arc::new(|_: ReceivedMessage<HashMap<String, String>>| {});
        let mut message_layer1 = MessageLayer::new(node1.p2p, node1.keypair, handler_noop);

        let mut content = HashMap::new();
        content.insert("test".to_string(), "value".to_string());

        message_layer1
            .send(content.clone(), TEST_TOPIC)
            .await
            .unwrap();

        match timeout(Duration::from_secs(3), rx).await {
            Ok(Ok(received_msg)) => {
                assert_eq!(received_msg.content.get("test"), Some(&"value".to_string()));
                assert_eq!(received_msg.topic, TEST_TOPIC.to_string());
            }
            Ok(Err(e)) => panic!("Channel error: {:?}", e),
            Err(_) => panic!("Timed out waiting for message"),
        }
    }
}
