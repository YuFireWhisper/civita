use std::sync::Arc;

use libp2p::{request_response, PeerId, Swarm};
use tokio::sync::{mpsc, Mutex};

use crate::network::behaviour::Behaviour;

mod network;

type Result<T, E = Error> = std::result::Result<T, E>;
type Event = request_response::Event<Vec<u8>, Vec<u8>>;
type ResponseChannel = request_response::ResponseChannel<Vec<u8>>;

const CHANNEL_SIZE: usize = 100;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] network::Error),
}

pub enum Message {
    Request {
        peer: PeerId,
        request: Vec<u8>,
        channel: ResponseChannel,
    },
    Response {
        peer: PeerId,
        response: Vec<u8>,
    },
}

pub enum RequestResponse {
    Network(network::RequestResponse),
}

impl Message {
    pub fn new_request(peer: PeerId, request: Vec<u8>, channel: ResponseChannel) -> Self {
        Self::Request {
            peer,
            request,
            channel,
        }
    }

    pub fn new_response(peer: PeerId, response: Vec<u8>) -> Self {
        Self::Response { peer, response }
    }
}

impl RequestResponse {
    pub fn new_network(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        RequestResponse::Network(network::RequestResponse::new(swarm))
    }

    pub async fn handle_event_network(&self, event: Event) -> Result<()> {
        match self {
            Self::Network(n) => n.handle_event(event).await.map_err(Error::from),
        }
    }

    pub fn subscribe(&self, topic: u8) -> mpsc::Receiver<Message> {
        match self {
            Self::Network(n) => n.subscribe(topic),
        }
    }

    pub fn unsubscribe(&self, topic: u8) {
        match self {
            Self::Network(n) => n.unsubscribe(topic),
        }
    }

    pub async fn send_request(&self, peer_id: libp2p::PeerId, request: Vec<u8>, topic: u8) {
        match self {
            Self::Network(n) => n.send_request(peer_id, request, topic).await,
        }
    }

    pub async fn send_response(
        &self,
        ch: ResponseChannel,
        response: Vec<u8>,
        topic: u8,
    ) -> Result<()> {
        match self {
            Self::Network(n) => n
                .send_response(ch, response, topic)
                .await
                .map_err(Error::from),
        }
    }
}
