use std::io;

use crate::network::behaviour;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Dial(#[from] libp2p::swarm::DialError),

    #[error("{0}")]
    TransportIo(#[from] libp2p::TransportError<io::Error>),

    #[error("{0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Lock contention")]
    LockContention,

    #[error("{0}")]
    Behaviour(#[from] behaviour::Error),
}
