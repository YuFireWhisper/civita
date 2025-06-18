use std::mem;

use bincode::error::DecodeError;
use generic_array::{ArrayLength, GenericArray};

use crate::{
    crypto::{traits::hasher::HashArray, Hasher},
    network::transport,
};

pub mod node;

pub use node::Node;

type KeyArray<H> = GenericArray<<H as HasherConfig>::BanchingFactor, <H as HasherConfig>::Depth>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("{0}")]
    Decode(#[from] DecodeError),
}

pub trait HasherConfig: Hasher + Send + Sync + 'static {
    const DEPTH: usize;
    const BANCHING_FACTOR_SIZE: usize;

    type BanchingFactor: Ord + Send + Sync + 'static + Sized + Copy + std::hash::Hash;
    type BanchingFactorLen: ArrayLength;
    type Depth: ArrayLength;

    fn convert_to_key(hash: HashArray<Self>) -> KeyArray<Self>;
    fn convert_to_hash(key: KeyArray<Self>) -> HashArray<Self>;
    fn serialize_banching_factor(
        factor: &Self::BanchingFactor,
    ) -> GenericArray<u8, Self::BanchingFactorLen>;
    fn deserialize_banching_factor(bytes: &[u8]) -> Option<Self::BanchingFactor>;
}

impl HasherConfig for sha2::Sha256 {
    const DEPTH: usize = 16;
    const BANCHING_FACTOR_SIZE: usize = 2;

    type BanchingFactor = u16;
    type BanchingFactorLen = generic_array::typenum::U2;
    type Depth = generic_array::typenum::U16;

    fn convert_to_key(hash: HashArray<Self>) -> KeyArray<Self> {
        unsafe { mem::transmute::<HashArray<Self>, KeyArray<Self>>(hash) }
    }

    fn convert_to_hash(key: KeyArray<Self>) -> HashArray<Self> {
        unsafe { mem::transmute::<KeyArray<Self>, HashArray<Self>>(key) }
    }

    fn serialize_banching_factor(
        factor: &Self::BanchingFactor,
    ) -> GenericArray<u8, Self::BanchingFactorLen> {
        GenericArray::from_array(factor.to_be_bytes())
    }

    fn deserialize_banching_factor(bytes: &[u8]) -> Option<Self::BanchingFactor> {
        match bytes.len() {
            2 => Some(u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => None,
        }
    }
}
