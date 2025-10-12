pub mod consensus;
pub mod crypto;
pub mod event;
pub mod network;
pub mod resident;
pub mod traits;
pub mod ty;
pub mod utils;

pub use libp2p::identity;
pub use libp2p::Multiaddr;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
