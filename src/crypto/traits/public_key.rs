use std::{fmt::Debug, hash::Hash};

use crate::crypto;

pub trait PublicKey: Clone + Debug + Eq + Hash + Sized + Sync + Send + 'static {
    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error>;
    fn to_bytes(&self) -> Vec<u8>;
}
