use sha2::Digest;

pub type Multihash = multihash::Multihash<64>;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(PartialEq, Eq)]
pub enum Code {
    Sha2256,
}

pub trait Hasher: 'static + Send + Sync + Sized {
    const BLOCK_SIZE_IN_BYTES: usize;
    const OUTPUT_SIZE_IN_BYTES: usize;

    fn hash(msg: &[u8]) -> Multihash;
}

impl Code {
    pub fn as_u64(self) -> u64 {
        match self {
            Code::Sha2256 => 0x01,
        }
    }
}

impl Hasher for sha2::Sha256 {
    const BLOCK_SIZE_IN_BYTES: usize = 64;
    const OUTPUT_SIZE_IN_BYTES: usize = 32;

    fn hash(msg: &[u8]) -> Multihash {
        let digest = sha2::Sha256::digest(msg);
        Multihash::wrap(Code::Sha2256.as_u64(), &digest).expect("Failed to wrap hash")
    }
}
