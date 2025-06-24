use std::mem;

use bincode::error::DecodeError;
use generic_array::{ArrayLength, GenericArray};

use crate::{
    crypto::{traits::hasher::HashArray, Hasher},
    network::transport,
    traits::{ConstantSize, Serializable},
};

pub mod node;

pub use node::Node;

type KeyArray<H> = GenericArray<<H as Config>::BanchingFactor, <H as Config>::Depth>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Decode(#[from] DecodeError),

    #[error("Node not found")]
    NodeNotFound,
}

pub trait Config: Hasher + Send + Sync + 'static {
    type BanchingFactor: Ord
        + Send
        + Sync
        + 'static
        + Sized
        + Copy
        + std::hash::Hash
        + Serializable
        + ConstantSize;
    type Depth: ArrayLength;

    fn convert_to_key(hash: HashArray<Self>) -> KeyArray<Self>;
    fn convert_to_hash(key: KeyArray<Self>) -> HashArray<Self>;
}

impl Config for sha2::Sha256 {
    type BanchingFactor = u16;
    type Depth = generic_array::typenum::U16;

    fn convert_to_key(hash: HashArray<Self>) -> KeyArray<Self> {
        unsafe { mem::transmute::<HashArray<Self>, KeyArray<Self>>(hash) }
    }

    fn convert_to_hash(key: KeyArray<Self>) -> HashArray<Self> {
        unsafe { mem::transmute::<KeyArray<Self>, HashArray<Self>>(key) }
    }
}
