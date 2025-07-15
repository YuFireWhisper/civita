use std::sync::Arc;

use libp2p::{
    request_response::{self, ResponseChannel},
    Swarm,
};
use tokio::sync::Mutex;

use crate::network::behaviour::Behaviour;

mod network;

type Event = request_response::Event<Vec<u8>, Vec<u8>>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] network::Error),
}

pub enum RequestResponse {
    Network(network::RequestResponse),
}

impl RequestResponse {
    pub fn new_network(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        Self::Network(network::RequestResponse::new(swarm))
    }

    pub async fn handle_event_network(&self, event: Event) -> Result<()> {
        match self {
            Self::Network(network) => network.handle_event(event).await.map_err(Error::from),
        }
    }

    pub async fn send_request_network(
        &self,
        peer_id: libp2p::PeerId,
        request: Vec<u8>,
    ) -> Result<()> {
        match self {
            Self::Network(network) => network
                .send_request(peer_id, request)
                .await
                .map_err(Error::from),
        }
    }

    pub async fn send_response_network(
        &self,
        ch: ResponseChannel<Vec<u8>>,
        response: Vec<u8>,
    ) -> Result<()> {
        match self {
            Self::Network(network) => network
                .send_response(ch, response)
                .await
                .map_err(Error::from),
        }
    }
}
