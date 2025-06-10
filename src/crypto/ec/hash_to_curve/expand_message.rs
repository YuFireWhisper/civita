pub mod xmd;

pub use xmd::Xmd;

use crate::crypto::traits::hasher::Hasher;

pub trait ExpandMessage<H: Hasher> {
    fn expand_message(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8>;
}
