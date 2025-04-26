use std::collections::HashSet;

use dashmap::DashMap;
use tokio::sync::mpsc::Sender as TokioSender;

use crate::{
    identity::resident_id::ResidentId,
    network::transport::libp2p_transport::protocols::gossipsub::Message,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("No sender found for topic: {0:?}")]
    NoSender(Vec<u8>),

    #[error("Failed to send message: {0}")]
    SendFailed(#[from] tokio::sync::mpsc::error::TrySendError<Message>),
}

#[derive(Debug)]
#[derive(Default)]
pub struct Dispatcher {
    senders: DashMap<Vec<u8>, (Option<HashSet<ResidentId>>, TokioSender<Message>)>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        topic: Vec<u8>,
        limited: Option<HashSet<ResidentId>>,
        tx: TokioSender<Message>,
    ) {
        self.senders.insert(topic, (limited, tx));
    }

    pub fn unregister(&self, topic: &[u8]) {
        self.senders.remove(topic);
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
        tx.try_send(message).map_err(|e| Error::SendFailed(e))?;

        Ok(())
    }

    pub fn remove_dead(&self) {
        self.senders.retain(|_, (_, tx)| !tx.is_closed());
    }
}
