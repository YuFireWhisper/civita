pub mod chain_config;
pub mod consensus;
pub mod crypto;
pub mod event;
pub mod network;
pub mod resident;
pub mod ty;
pub mod utils;
pub mod validator;

pub use chain_config::ChainConfig;
pub use libp2p::identity;
pub use libp2p::Multiaddr;
pub use validator::ValidatorEngine;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();
