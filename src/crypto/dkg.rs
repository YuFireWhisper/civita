use std::{collections::HashSet, future::Future};

use curv::{cryptographic_primitives::hashing::Digest, elliptic::curves::Curve};
use libp2p::PeerId;

use crate::crypto::dkg::classic::keypair::PublicKey;
use crate::crypto::dkg::classic::signature::Signature;
use crate::crypto::dkg::classic::Error;
use crate::network::transport::Transport;

pub trait Dkg<T: Transport + 'static, E: Curve> {
    fn start<H: Digest + Clone>(
        &mut self,
        self_peer: PeerId,
        other_peers: HashSet<PeerId>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    fn stop(&mut self) -> impl Future<Output = ()> + Send;
    fn sign(
        &self,
        msg_to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Signature<E>, Error>> + Send;
    fn pub_key(&self) -> Option<&PublicKey<E>>;
}

pub mod classic;
