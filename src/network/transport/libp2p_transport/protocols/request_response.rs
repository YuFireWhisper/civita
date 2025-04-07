use std::sync::Arc;

use libp2p::PeerId;

use crate::network::transport::libp2p_transport::{
    behaviour::Behaviour,
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

#[derive(Debug)]
#[derive(Default)]
pub struct ConfigBuilder {
    channel_size: Option<usize>,
}

impl ConfigBuilder {
    const DEFAULT_CHANNEL_SIZE: usize = 1000;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_channel_size(mut self, size: usize) -> Self {
        self.channel_size = Some(size);
        self
    }

    pub fn build(self) -> Config {
        Config {
            channel_size: self.channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE),
        }
    }
}

pub struct RequestResponse {
    swarm: Arc<tokio::sync::Mutex<libp2p::Swarm<Behaviour>>>,
    dispatcher: Dispatcher<PeerId, Message>,
    config: Config,
}

impl RequestResponse {
    pub fn new(swarm: Arc<tokio::sync::Mutex<libp2p::Swarm<Behaviour>>>, config: Config) -> Self {
        Self {
            swarm,
            dispatcher: Dispatcher::new(),
            config,
        }
    }

    pub fn handle_event(
        &self,
        event: libp2p::request_response::Event<Request, Response>,
    ) -> Result<()> {
        let message = Message::try_from_request_response_event(event)?;
        self.dispatcher.dispatch(message).map_err(Error::from)
    }

    pub fn listen<I>(&self, peers: I) -> tokio::sync::mpsc::Receiver<Message>
    where
        I: IntoIterator<Item = PeerId>,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(self.config.channel_size);
        self.dispatcher.register_all(peers, &tx);
        rx
    }

    pub async fn request(&self, peer_id: &PeerId, request: impl Into<Request>) {
        self.swarm
            .lock()
            .await
            .behaviour_mut()
            .request_response_mut()
            .send_request(peer_id, request.into());
    }
}
