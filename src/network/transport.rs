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

use crate::network::transport::libp2p_transport::message::Message;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Listener {
    Topic(String),
    Peer(Vec<PeerId>),
}

pub trait Transport: Send + Sync {
    fn dial(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>>;
    fn listen(
        &self,
        filter: Listener,
    ) -> Pin<Box<dyn Future<Output = Result<Receiver<Message>, Error>> + Send + '_>>;
    fn send(
        &self,
        message: Message,
    ) -> Pin<Box<dyn Future<Output = Result<Option<MessageId>, Error>> + Send + '_>>;
    fn receive(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
    fn stop_receive(&self) -> Result<(), Error>;
}
