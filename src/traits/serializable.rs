use std::io::{Read, Write};

pub mod b_tree_map;
pub mod b_tree_set;
pub mod box_;
pub mod hash_map;
pub mod message_id;
pub mod multiaddr;
pub mod multihash;
pub mod numeric;
pub mod option;
pub mod peer_id;
pub mod string;
pub mod tuple;
pub mod vec;

#[derive(Debug)]
pub struct Error(pub String);

pub trait Serializable: Sized {
    fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error>;
    fn to_writer<W: Write>(&self, writer: &mut W);
    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let mut reader = slice;
        Self::from_reader(&mut reader)
    }
    fn to_vec(&self) -> Vec<u8> {
        let mut writer = Vec::new();
        self.to_writer(&mut writer);
        writer
    }
}

// pub trait ConstantSize {
//     const SIZE: usize;
// }

impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}
