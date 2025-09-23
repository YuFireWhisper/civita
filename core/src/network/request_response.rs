use std::sync::Arc;

use libp2p::{request_response, PeerId, Swarm};
use tokio::sync::{mpsc, Mutex};

use crate::network::behaviour::Behaviour;

type Result<T, E = Error> = std::result::Result<T, E>;
type Event = request_response::Event<Vec<u8>, Vec<u8>>;
type ResponseChannel = request_response::ResponseChannel<Vec<u8>>;

const CHANNEL_SIZE: usize = 100;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to send response")]
    SendResponse,

    #[error(transparent)]
    Channel(#[from] mpsc::error::SendError<Message>),
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

pub struct RequestResponse {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    tx: mpsc::Sender<Message>,
    rx: Mutex<mpsc::Receiver<Message>>,
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
    pub fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        Self {
            swarm,
            tx,
            rx: Mutex::new(rx),
        }
    }

    pub async fn handle_event(&self, event: Event) -> Result<()> {
        use libp2p::request_response::Message as Libp2pMessage;

        if let Event::Message { peer, message, .. } = event {
            match message {
                Libp2pMessage::Request {
                    request, channel, ..
                } => {
                    let msg = Message::new_request(peer, request, channel);
                    self.tx.send(msg).await?;
                }
                Libp2pMessage::Response { response, .. } => {
                    let msg = Message::new_response(peer, response);
                    self.tx.send(msg).await?;
                }
            }
        }

        Ok(())
    }

    pub async fn send_request(&self, peer_id: PeerId, request: Vec<u8>) {
        let mut swarm = self.swarm.lock().await;
        let _ = swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_request(&peer_id, request);
    }

    pub async fn send_response(&self, channel: ResponseChannel, response: Vec<u8>) -> Result<()> {
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_response(channel, response)
            .map_err(|_| Error::SendResponse)?;
        Ok(())
    }

    pub async fn recv(&self) -> Option<Message> {
        self.rx.lock().await.recv().await
    }
}
