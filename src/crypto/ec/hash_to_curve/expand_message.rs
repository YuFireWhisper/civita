pub mod xmd;

pub use xmd::Xmd;

pub trait ExpandMessage {
    fn expand_message(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8>;
}
