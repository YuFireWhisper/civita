use multihash_derive::MultihashDigest;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(MultihashDigest)]
#[mh(alloc_size = 64)]
#[repr(u8)]
pub enum Hasher {
    #[default]
    #[mh(code = 0x01, hasher = multihash_codetable::Sha2_256)]
    Sha2_256,

    #[mh(code = 0x02, hasher = multihash_codetable::Sha2_512)]
    Sha2_512,

    #[mh(code = 0x03, hasher = multihash_codetable::Sha3_224)]
    Sha3_224,

    #[mh(code = 0x04, hasher = multihash_codetable::Sha3_256)]
    Sha3_256,

    #[mh(code = 0x05, hasher = multihash_codetable::Sha3_384)]
    Sha3_384,

    #[mh(code = 0x06, hasher = multihash_codetable::Sha3_512)]
    Sha3_512,

    #[mh(code = 0x07, hasher = multihash_codetable::Blake3_256)]
    Blake3,
}

impl Hasher {
    pub fn validate(hash: &Multihash, data: &[u8]) -> bool {
        let Ok(hasher) = Self::try_from(hash.code()) else {
            return false;
        };
        &hasher.digest(data) == hash
    }
}
