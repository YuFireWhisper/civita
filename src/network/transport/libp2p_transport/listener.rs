use std::collections::HashMap;

use libp2p::PeerId;
use thiserror::Error;
use tokio::sync::mpsc::{error::TrySendError, Sender};

use crate::network::transport::libp2p_transport::message::Message;

#[derive(Debug, Error)]
pub enum Error {
    #[error("No such item")]
    NoSuchItem,
    #[error("Failed to send message: {0}")]
    SendFailed(String),
}

impl From<TrySendError<Message>> for Error {
    fn from(err: TrySendError<Message>) -> Self {
        Error::SendFailed(err.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

pub(super) struct Listener {
    topics: HashMap<String, Sender<Message>>,
    peers: HashMap<PeerId, Sender<Message>>,
}

impl Listener {
    pub fn new() -> Self {
        let topics = HashMap::new();
        let peers = HashMap::new();

        Self { topics, peers }
    }

    pub fn add_topic(&mut self, topic: impl Into<String>, tx: &Sender<Message>) {
        self.topics.insert(topic.into(), tx.clone());
    }

    pub fn add_topics(
        &mut self,
        topics: impl IntoIterator<Item = impl Into<String>>,
        tx: &Sender<Message>,
    ) {
        topics
            .into_iter()
            .for_each(|topic| self.add_topic(topic, tx));
    }

    pub fn add_peer(&mut self, peer: PeerId, tx: &Sender<Message>) {
        self.peers.insert(peer, tx.clone());
    }

    pub fn add_peers(&mut self, peers: impl IntoIterator<Item = PeerId>, tx: &Sender<Message>) {
        peers.into_iter().for_each(|peer| self.add_peer(peer, tx));
    }

    pub fn remove_dead_channels(&mut self) {
        self.topics.retain(|_, tx| !tx.is_closed());
        self.peers.retain(|_, tx| !tx.is_closed());
    }

    pub fn broadcast_to_topic(&self, topic: &str, message: Message) -> Result<()> {
        let sender = self.topics.get(topic).ok_or(Error::NoSuchItem)?;
        sender.try_send(message).map_err(Error::from)
    }

    pub fn broadcast_to_peer(&self, peer: &PeerId, message: Message) -> Result<()> {
        let sender = self.peers.get(peer).ok_or(Error::NoSuchItem)?;
        sender.try_send(message).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;
    use tokio::sync::mpsc::channel;

    use crate::network::transport::libp2p_transport::Listener;

    #[test]
    fn create() {
        let result = Listener::new();

        assert!(result.topics.is_empty());
        assert!(result.peers.is_empty());
    }

    #[test]
    fn add_topic_success() {
        let mut listener = Listener::new();
        let topic = "topic";
        let (tx, _) = channel(1);

        listener.add_topic(topic, &tx);

        assert_eq!(listener.topics.len(), 1);
    }

    #[test]
    fn add_topics_success() {
        let mut listener = Listener::new();
        let topics = vec!["topic1", "topic2"];
        let (tx, _) = channel(1);

        listener.add_topics(topics, &tx);

        assert_eq!(listener.topics.len(), 2);
    }

    #[test]
    fn add_peer_success() {
        let mut listener = Listener::new();
        let peer = PeerId::random();
        let (tx, _) = channel(1);

        listener.add_peer(peer, &tx);

        assert_eq!(listener.peers.len(), 1);
    }

    #[test]
    fn add_peers_success() {
        let mut listener = Listener::new();
        let peers = vec![PeerId::random(), PeerId::random()];
        let (tx, _) = channel(1);

        listener.add_peers(peers, &tx);

        assert_eq!(listener.peers.len(), 2);
    }
}
