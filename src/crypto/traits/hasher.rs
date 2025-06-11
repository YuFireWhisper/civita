use generic_array::{ArrayLength, GenericArray};
use sha2::Digest;

pub type HashArray<H> = GenericArray<u8, <H as Hasher>::OutputSizeInBytes>;

pub trait Hasher: 'static + Send + Sync + Sized {
    const BLOCK_SIZE_IN_BYTES: usize;
    const OUTPUT_SIZE_IN_BIT: usize;

    type OutputSizeInBytes: ArrayLength;

    fn hash(msg: &[u8]) -> HashArray<Self>;
}

impl Hasher for sha2::Sha256 {
    const BLOCK_SIZE_IN_BYTES: usize = 64;
    const OUTPUT_SIZE_IN_BIT: usize = 256;

    type OutputSizeInBytes = generic_array::typenum::U32;

    fn hash(input: &[u8]) -> HashArray<Self> {
        GenericArray::from_array(sha2::Sha256::digest(input).into())
    }
}
