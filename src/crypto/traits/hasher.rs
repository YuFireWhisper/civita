use generic_array::{ArrayLength, GenericArray};
use sha2::Digest;

pub type Output<N> = GenericArray<u8, N>;

pub trait Hasher {
    const BLOCK_SIZE_IN_BYTES: usize;
    const OUTPUT_SIZE_IN_BIT: usize;

    type OutputSizeInBytes: ArrayLength;

    fn hash(msg: &[u8]) -> Output<Self::OutputSizeInBytes>;
}

impl Hasher for sha2::Sha256 {
    const OUTPUT_SIZE_IN_BIT: usize = 256;
    const BLOCK_SIZE_IN_BYTES: usize = 64;

    type OutputSizeInBytes = generic_array::typenum::U32;

    fn hash(input: &[u8]) -> Output<Self::OutputSizeInBytes> {
        GenericArray::from_array(sha2::Sha256::digest(input).into())
    }
}
