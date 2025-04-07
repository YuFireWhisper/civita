use std::{collections::HashSet, io};

use crate::{
    crypto::dkg::Data,
    network::transport::libp2p_transport::{
        behaviour, message,
        protocols::{
            gossipsub, kad,
            request_response::{self, payload::Request},
        },
    },
};

pub mod libp2p_transport;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("{0}")]
    Dial(#[from] libp2p::swarm::DialError),
    #[error("{0}")]
    Subscribe(#[from] libp2p::gossipsub::SubscriptionError),
    #[error("{0}")]
    Publish(#[from] libp2p::gossipsub::PublishError),
    #[error("{0}")]
    Behaviour(#[from] behaviour::Error),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Message(#[from] message::Error),
    #[error("{0}")]
    KadMessage(#[from] kad::message::Error),
    #[error("Gossipsub error: {0}")]
    Gossipsub(#[from] gossipsub::Error),
    #[error("Kademlia error: {0}")]
    Kademlia(#[from] kad::Error),
    #[error("Request Response error: {0}")]
    RequestResponse(#[from] request_response::Error),
    #[error("Listener failed: {0}")]
    ListenerFailed(String),
    #[error("Failed to bind to address within timeout")]
    BindTimeout,
    #[error("Lock contention")]
    LockContention,
    #[error("No any peer listen on the topic: {0}")]
    NoPeerListen(String),
    #[error("Store error: {0}")]
    Store(#[from] libp2p::kad::store::Error),
    #[error("Put error: {0}")]
    KadPut(String),
    #[error("Chnnel closed")]
    ChannelClosed,
    #[error("Kad put timeout")]
    KadPutTimeout,
}

#[mockall::automock]
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn dial(&self, peer_id: libp2p::PeerId, addr: libp2p::Multiaddr) -> Result<(), Error>;
    async fn listen_on_topic(
        &self,
        topic: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<gossipsub::Message>, Error>;
    async fn listen_on_peers(
        &self,
        peers: HashSet<libp2p::PeerId>,
    ) -> tokio::sync::mpsc::Receiver<request_response::Message>;
    async fn publish(
        &self,
        topic: &str,
        payload: gossipsub::Payload,
    ) -> Result<libp2p::gossipsub::MessageId, Error>;
    async fn request(&self, peer_id: &libp2p::PeerId, request: Request);
    async fn put(&self, payload: kad::Payload, signature: Data) -> Result<(), Error>;
    fn self_peer(&self) -> libp2p::PeerId;
}
