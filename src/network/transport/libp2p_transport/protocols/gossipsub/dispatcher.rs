use std::collections::HashSet;

use dashmap::DashMap;
use libp2p::PeerId;
use tokio::sync::mpsc::Sender as TokioSender;

use crate::network::transport::libp2p_transport::protocols::gossipsub::Message;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("No sender found for topic: {0}")]
    NoSender(String),

    #[error("Failed to send message: {0}")]
    SendFailed(Box<tokio::sync::mpsc::error::TrySendError<Message>>),
}

#[derive(Debug)]
#[derive(Default)]
pub struct Dispatcher {
    senders: DashMap<String, (Option<HashSet<PeerId>>, TokioSender<Message>)>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        topic: String,
        limited: Option<HashSet<PeerId>>,
        tx: TokioSender<Message>,
    ) {
        self.senders.insert(topic, (limited, tx));
    }

    pub fn dispatch(&self, message: Message) -> Result<()> {
        let entry = match self.senders.get(&message.topic) {
            Some(entry) => entry,
            None => return Err(Error::NoSender(message.topic)),
        };

        if let Some(limited) = &entry.0 {
            if !limited.contains(&message.source) {
                return Ok(());
            }
        }

        let tx = &entry.1;
        tx.try_send(message)?;

        Ok(())
    }

    pub fn remove_dead(&self) {
        self.senders.retain(|_, (_, tx)| !tx.is_closed());
    }
}

impl From<tokio::sync::mpsc::error::TrySendError<Message>> for Error {
    fn from(e: tokio::sync::mpsc::error::TrySendError<Message>) -> Self {
        Error::SendFailed(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{gossipsub::MessageId, PeerId};
    use tokio::sync::mpsc;

    use crate::network::transport::libp2p_transport::protocols::gossipsub::{
        dispatcher::Dispatcher, Message, Payload,
    };

    const MESSAGE_ID: &[u8] = &[1, 2, 3, 4, 5];
    const TOPIC: &str = "test-topic";
    const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

    fn create_test_message(topic: &str, source_peer_id: PeerId) -> Message {
        Message {
            message_id: MessageId::from(MESSAGE_ID),
            source: source_peer_id,
            topic: topic.to_string(),
            payload: Payload::Raw(PAYLOAD.to_vec()),
            committee_signature: None,
        }
    }

    #[tokio::test]
    async fn dispatch_to_registered_topic_succeeds() {
        let dispatcher = Dispatcher::new();
        let (tx, mut rx) = mpsc::channel(10);
        dispatcher.register(TOPIC.to_string(), None, tx);

        let peer_id = PeerId::random();
        let message = create_test_message(TOPIC, peer_id);
        let result = dispatcher.dispatch(message.clone());

        assert!(result.is_ok());
        let received = rx.try_recv().unwrap();
        assert_eq!(received, message);
    }
}
