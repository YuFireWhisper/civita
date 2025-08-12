type Multihash = libp2p::multihash::Multihash<64>;

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[repr(u8)]
pub enum Code {
    #[default]
    Sha2_256 = 0x01,
}

impl Code {
    pub fn from_u8(code: u64) -> Option<Self> {
        match code {
            0x01 => Some(Code::Sha2_256),
            _ => None,
        }
    }

    pub fn digest(data: &[u8]) -> Multihash {
        Self::default().digest_with(data)
    }

    pub fn digest_with(&self, data: &[u8]) -> Multihash {
        match self {
            Code::Sha2_256 => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(data);
                Multihash::wrap(Code::Sha2_256 as u64, &hash)
                    .expect("SHA2_256 hash should always be valid")
            }
        }
    }

    pub fn is_supported_code(hash: &Multihash) -> bool {
        Self::from_u8(hash.code() as u64).is_some()
    }
}
