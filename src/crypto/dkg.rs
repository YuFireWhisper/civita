pub mod classic;

use std::sync::Arc;

use libp2p::PeerId;

use crate::network::transport::libp2p_transport::Libp2pTransport;

pub trait Dkg {
    type Error;

    fn new(transport: Arc<Libp2pTransport>, peer_ids: Vec<PeerId>, threshold_ratio: usize) -> Self;
    fn init(&self) -> Result<(), Self::Error>;
    fn sign(&self, message: Vec<u8>) -> Vec<u8>;
    fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool;
}
