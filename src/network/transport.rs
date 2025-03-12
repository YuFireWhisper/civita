pub mod libp2p_transport;

use std::{future::Future, io, pin::Pin};

use libp2p::{gossipsub::MessageId, swarm, Multiaddr, PeerId};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::{
    behaviour,
    message::{request_response, Message},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("{0}")]
    Dial(#[from] swarm::DialError),
    #[error("{0}")]
    Subscribe(#[from] libp2p::gossipsub::SubscriptionError),
    #[error("{0}")]
    Publish(#[from] libp2p::gossipsub::PublishError),
    #[error("{0}")]
    P2PBehaviour(#[from] behaviour::Error),
    #[error("Failed to lock")]
    LockError,
    #[error("{0}")]
    RequestResponse(#[from] request_response::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionFilter {
    Topic(String),
    Peer(Vec<PeerId>),
}

pub trait Transport {
    fn dial(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
    fn subscribe(
        &self,
        filter: SubscriptionFilter,
    ) -> Pin<Box<dyn Future<Output = Result<Receiver<Message>>> + Send>>;
    fn send(
        &self,
        message: Message,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>>> + Send>>;
    fn receive(&self) -> Pin<Box<dyn Future<Output = ()>>>;
    fn stop_receive(&self) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}
