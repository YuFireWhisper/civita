use sha2::Digest;

use crate::crypto::ec::hash_to_curve::config::Hasher;

impl Hasher for sha2::Sha256 {
    const OUTPUT_SIZE_IN_BIT: usize = 256;
    const BLOCK_SIZE_IN_BYTES: usize = 64;

    fn hash(input: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(input).to_vec()
    }
}
