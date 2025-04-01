use crate::network::transport::libp2p_transport::mock_transport::MockTransport;
use crate::network::transport::Transport;
use std::{collections::HashSet, future::Future};

use libp2p::PeerId;
use mockall::automock;

pub mod classic;
pub mod signature;

pub use signature::{Data, Scheme};

#[automock(type Error=String;)]
pub trait Dkg<T: Transport + 'static> {
    type Error;

    fn start(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn stop(&mut self);
    fn sign(&self, msg_to_sign: Vec<u8>) -> impl Future<Output = Result<Data, Self::Error>> + Send;
    fn validate(&self, msg_to_sign: Vec<u8>, signature: Data) -> Result<bool, Self::Error>;
    fn public_key(&self) -> Option<Vec<u8>>;
}

#[automock(type T=MockTransport; type D=MockDkg<MockTransport>;)]
pub trait DkgFactory {
    type T: Transport + 'static;
    type D: Dkg<Self::T>;

    fn create(&self) -> Self::D;
}
