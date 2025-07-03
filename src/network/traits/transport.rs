use libp2p::PeerId;

use crate::{
    crypto::SecretKey,
    network::traits::{gossipsub::Gossipsub, storage::Storage},
};

#[async_trait::async_trait]
pub trait Transport: Send + Sync + 'static {
    type Storage: Storage;
    type Gossipsub: Gossipsub;

    fn storage(&self) -> Self::Storage;
    fn gossipsub(&self) -> Self::Gossipsub;
    fn local_peer_id(&self) -> PeerId;
    fn secret_key(&self) -> &SecretKey;
}
