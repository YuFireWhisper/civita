pub type HashArray = [u8; 32];

pub const HASH_ARRAY_LENGTH: usize = std::mem::size_of::<HashArray>();

pub const USIZE_LENGTH: usize = std::mem::size_of::<usize>();
pub const U64_LENGTH: usize = std::mem::size_of::<u64>();
pub const U32_LENGTH: usize = std::mem::size_of::<u32>();

pub const DEFAULT_NETWORK_LATENCY: tokio::time::Duration = tokio::time::Duration::from_secs(3);
