use std::io;

use crate::network::behaviour;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Dial(#[from] libp2p::swarm::DialError),

    #[error(transparent)]
    TransportIo(#[from] libp2p::TransportError<io::Error>),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Lock contention")]
    LockContention,

    #[error(transparent)]
    Behaviour(#[from] behaviour::Error),
}
