pub mod libp2p_transport;

use std::{future::Future, io};

use libp2p::{
    gossipsub::{MessageId, PublishError, SubscriptionError},
    swarm::DialError,
    Multiaddr, PeerId, TransportError,
};
use libp2p_transport::behaviour;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::message::Message;

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
    #[error("Failed to lock")]
    LockError,
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionFilter {
    Topic(String),
    Peer(Vec<PeerId>),
}

pub trait Transport: Send + Sync {
    fn dial(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> impl Future<Output = Result<()>> + Send;
    fn subscribe(
        &self,
        filter: SubscriptionFilter,
    ) -> impl Future<Output = Result<Receiver<Message>>> + Send;
    fn send(
        &self,
        message: Message,
    ) -> impl Future<Output = Result<Option<MessageId>>> + Send;
    fn receive(&self) -> impl Future<Output = ()>;
    fn stop_receive(&self) -> Result<()>;
}
