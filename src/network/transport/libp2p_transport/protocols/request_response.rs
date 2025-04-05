use libp2p::PeerId;

use crate::network::transport::libp2p_transport::{
    dispatcher::{self, Dispatcher},
    protocols::request_response::payload::{Request, Response},
};

pub mod message;
pub mod payload;

pub use message::Message;
pub use payload::Payload;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Message error: {0}")]
    Message(#[from] message::Error),

    #[error("Dispatch error: {0}")]
    Dispatch(#[from] dispatcher::Error),
}

pub struct Config {
    pub channel_size: usize,
}

pub struct RequestResponse {
    dispatcher: Dispatcher<PeerId, Message>,
    config: Config,
}

impl RequestResponse {
    pub fn new(config: Config) -> Self {
        Self {
            dispatcher: Dispatcher::new(),
            config,
        }
    }

    pub fn listen(
        &self,
        peers: impl Iterator<Item = PeerId>,
    ) -> tokio::sync::mpsc::Receiver<Message> {
        let (tx, rx) = tokio::sync::mpsc::channel(self.config.channel_size);
        self.dispatcher.register_all(peers, &tx);
        rx
    }

    pub fn handle_event(
        &self,
        event: libp2p::request_response::Event<Request, Response>,
    ) -> Result<()> {
        let message = Message::try_from_request_response_event(event)?;
        self.dispatcher.dispatch(message).map_err(Error::from)
    }
}
