use std::{collections::HashSet, error::Error};

use crate::{
    crypto::dkg::Data,
    network::transport::libp2p_transport::protocols::{
        gossipsub, kad,
        request_response::{self, payload::Request},
    },
    MockError,
};

pub mod libp2p_transport;

pub use libp2p_transport::Libp2pTransport;

#[mockall::automock(type Error = MockError;)]
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    type Error: Error;

    async fn dial(
        &self,
        peer_id: libp2p::PeerId,
        addr: libp2p::Multiaddr,
    ) -> Result<(), Self::Error>;
    async fn listen_on_topic(
        &self,
        topic: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<gossipsub::Message>, Self::Error>;
    async fn listen_on_peers(
        &self,
        peers: HashSet<libp2p::PeerId>,
    ) -> tokio::sync::mpsc::Receiver<request_response::Message>;
    async fn publish(
        &self,
        topic: &str,
        payload: gossipsub::Payload,
    ) -> Result<libp2p::gossipsub::MessageId, Self::Error>;
    async fn request(&self, peer_id: &libp2p::PeerId, request: Request);
    async fn put(&self, payload: kad::Payload, signature: Data) -> Result<(), Self::Error>;
    async fn get(&self, key: kad::Key) -> Result<Option<kad::Payload>, Self::Error>;
    fn self_peer(&self) -> libp2p::PeerId;
    fn keypair(&self) -> &libp2p::identity::Keypair;
}
