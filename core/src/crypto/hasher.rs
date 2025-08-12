type Multihash = libp2p::multihash::Multihash<64>;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[repr(u8)]
pub enum Hasher {
    #[default]
    Sha2_256 = 0x01,
}

impl Hasher {
    pub fn from_u8(code: u64) -> Option<Self> {
        match code {
            0x01 => Some(Hasher::Sha2_256),
            _ => None,
        }
    }

    pub fn digest(data: &[u8]) -> Multihash {
        Self::default().digest_with(data)
    }

    pub fn digest_with(&self, data: &[u8]) -> Multihash {
        match self {
            Hasher::Sha2_256 => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(data);
                Multihash::wrap(Hasher::Sha2_256 as u64, &hash)
                    .expect("SHA2_256 hash should always be valid")
            }
        }
    }

    pub fn is_supported_code(hash: &Multihash) -> bool {
        Self::from_u8(hash.code()).is_some()
    }

    pub fn validate(hash: &Multihash, data: &[u8]) -> bool {
        if !Self::is_supported_code(hash) {
            return false;
        }

        let expected = Self::digest_with(&Self::from_u8(hash.code()).unwrap(), data);

        hash == &expected
    }
}
