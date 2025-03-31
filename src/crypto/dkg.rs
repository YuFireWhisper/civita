use std::{collections::HashSet, future::Future};

use libp2p::PeerId;

use crate::network::transport::Transport;

pub mod classic;
pub mod signature;

pub use signature::{Data, Scheme};

pub trait Dkg<T: Transport + 'static> {
    type Error;

    fn start(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn stop(&mut self);
    fn sign(
        &self,
        msg_to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Box<dyn signature::Data>, Self::Error>> + Send;
    fn validate(
        &self,
        msg_to_sign: Vec<u8>,
        signature: Box<dyn signature::Data>,
    ) -> Result<bool, Self::Error>;
}
