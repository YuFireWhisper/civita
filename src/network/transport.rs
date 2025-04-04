pub mod libp2p_transport;

use std::{collections::HashSet, io};

use async_trait::async_trait;
use libp2p::{
    gossipsub::{MessageId, PublishError, SubscriptionError},
    kad::store,
    swarm::DialError,
    Multiaddr, PeerId, TransportError,
};
use libp2p_transport::behaviour;
use mockall::automock;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use crate::{
    crypto::dkg::Data,
    network::transport::libp2p_transport::{
        listener,
        message::{self, Message},
        protocols::{gossipsub, kad, request_response::payload::Request},
    },
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] TransportError<io::Error>),
    #[error("{0}")]
    Dial(#[from] DialError),
    #[error("{0}")]
    Subscribe(#[from] SubscriptionError),
    #[error("{0}")]
    Publish(#[from] PublishError),
    #[error("{0}")]
    Behaviour(#[from] behaviour::Error),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Message(#[from] message::Error),
    #[error("{0}")]
    Listener(#[from] listener::Error),
    #[error("{0}")]
    KadMessage(#[from] kad::message::Error),
    #[error("Listener failed: {0}")]
    ListenerFailed(String),
    #[error("Failed to bind to address within timeout")]
    BindTimeout,
    #[error("Lock contention")]
    LockContention,
    #[error("No any peer listen on the topic: {0}")]
    NoPeerListen(String),
    #[error("Store error: {0}")]
    Store(#[from] store::Error),
    #[error("Put error: {0}")]
    KadPut(String),
    #[error("Chnnel closed")]
    ChannelClosed,
    #[error("Kad put timeout")]
    KadPutTimeout,
}

#[automock]
#[async_trait]
pub trait Transport: Send + Sync {
    async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<(), Error>;
    async fn listen_on_topic(&self, topic: &str) -> Result<Receiver<Message>, Error>;
    async fn listen_on_peers(&self, peers: HashSet<PeerId>) -> Result<Receiver<Message>, Error>;
    async fn publish(&self, topic: &str, payload: gossipsub::Payload) -> Result<MessageId, Error>;
    async fn request(&self, peer_id: PeerId, request: Request) -> Result<(), Error>;
    async fn put(&self, payload: kad::Payload, signature: Data) -> Result<(), Error>;
    fn self_peer(&self) -> PeerId;
}
