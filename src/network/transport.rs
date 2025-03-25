pub mod libp2p_transport;

use std::{future::Future, io, pin::Pin};

use libp2p::{
    gossipsub::{MessageId, PublishError, SubscriptionError},
    swarm::DialError,
    Multiaddr, PeerId, TransportError,
};
use libp2p_transport::behaviour;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use crate::network::transport::libp2p_transport::{
    listener,
    message::{self, Message},
    protocols::{gossipsub, request_response::payload::Request},
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
    #[error("Listener failed: {0}")]
    ListenerFailed(String),
    #[error("Failed to bind to address within timeout")]
    BindTimeout,
    #[error("Lock contention")]
    LockContention,
    #[error("No any peer listen on the topic: {0}")]
    NoPeerListen(String),
}

pub trait Transport: Send + Sync {
    fn dial(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>>;
    fn listen_on_topic<'a>(
        &'a self,
        topic: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Receiver<Message>, Error>> + Send + 'a>>;
    fn listen_on_peers<'a>(
        &'a self,
        peers: impl IntoIterator<Item = PeerId> + Send + 'a,
    ) -> Pin<Box<dyn Future<Output = Result<Receiver<Message>, Error>> + Send + 'a>>;
    fn publish<'a>(
        &'a self,
        topic: &'a str,
        payload: gossipsub::Payload,
    ) -> Pin<Box<dyn Future<Output = Result<MessageId, Error>> + Send + 'a>>;
    fn request<'a>(
        &'a self,
        peer_id: PeerId,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}
