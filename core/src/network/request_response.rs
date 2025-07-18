use std::sync::Arc;

use libp2p::{request_response, Swarm};
use tokio::sync::{mpsc, Mutex};

use crate::network::behaviour::Behaviour;

mod network;

type Result<T, E = Error> = std::result::Result<T, E>;
type Message = request_response::Message<Vec<u8>, Vec<u8>>;
type Event = request_response::Event<Vec<u8>, Vec<u8>>;
type ResponseChannel = request_response::ResponseChannel<Vec<u8>>;

const CHANNEL_SIZE: usize = 100;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] network::Error),
}

pub enum RequestResponse {
    Network {
        network: network::RequestResponse,
        rx: Mutex<mpsc::Receiver<Message>>,
    },
}

impl RequestResponse {
    pub fn new_network(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        let network = network::RequestResponse::new(swarm, tx);
        Self::Network {
            network,
            rx: Mutex::new(rx),
        }
    }

    pub async fn handle_event_network(&self, event: Event) -> Result<()> {
        match self {
            Self::Network { network, .. } => network.handle_event(event).await.map_err(Error::from),
        }
    }

    pub async fn send_request(&self, peer_id: libp2p::PeerId, request: Vec<u8>) {
        match self {
            Self::Network { network, .. } => {
                network.send_request(peer_id, request).await;
            }
        }
    }

    pub async fn send_reqeust_and_wait(
        &self,
        peer_id: libp2p::PeerId,
        request: Vec<u8>,
        timeout: tokio::time::Duration,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Network { network, .. } => network
                .send_request_and_wait(peer_id, request, timeout)
                .await
                .map_err(Error::from),
        }
    }

    pub async fn send_response(&self, ch: ResponseChannel, response: Vec<u8>) -> Result<()> {
        match self {
            Self::Network { network, .. } => network
                .send_response(ch, response)
                .await
                .map_err(Error::from),
        }
    }

    pub async fn recv(&self) -> Option<Message> {
        match self {
            Self::Network { rx, .. } => rx.lock().await.recv().await,
        }
    }
}
