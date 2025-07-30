use std::sync::Arc;

use dashmap::DashMap;
use libp2p::{PeerId, Swarm};
use tokio::sync::{mpsc, Mutex};

use crate::network::{
    behaviour::Behaviour,
    request_response::{Event, Message, ResponseChannel, CHANNEL_SIZE},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to send response")]
    SendResponse,

    #[error("{0}")]
    Send(String),

    #[error("Empty message")]
    EmptyMessage,
}

pub struct RequestResponse {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    txs: DashMap<u8, mpsc::Sender<Message>>,
}

impl RequestResponse {
    pub fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        Self {
            swarm,
            txs: DashMap::new(),
        }
    }

    pub async fn handle_event(&self, event: Event) -> Result<()> {
        use libp2p::request_response::Message as Libp2pMessage;

        if let Event::Message { peer, message, .. } = event {
            match message {
                Libp2pMessage::Request {
                    request, channel, ..
                } => {
                    self.handle_reqeust(peer, request, channel).await?;
                }
                Libp2pMessage::Response { response, .. } => {
                    self.handle_response(peer, response).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_reqeust(
        &self,
        peer: PeerId,
        mut request: Vec<u8>,
        channel: ResponseChannel,
    ) -> Result<()> {
        let topic = request.pop().ok_or(Error::EmptyMessage)?;

        if let Some(tx) = self.txs.get(&topic) {
            let msg = Message::new_request(peer, request, channel);
            tx.send(msg).await.map_err(Error::from)?;
        }

        Ok(())
    }

    async fn handle_response(&self, peer: PeerId, mut response: Vec<u8>) -> Result<()> {
        let topic = response.pop().ok_or(Error::EmptyMessage)?;

        if let Some(tx) = self.txs.get(&topic) {
            let message = Message::Response { peer, response };
            tx.send(message).await.map_err(Error::from)?;
        }

        Ok(())
    }

    pub fn subscribe(&self, topic: u8) -> mpsc::Receiver<Message> {
        let (tx, rx) = mpsc::channel(CHANNEL_SIZE);
        self.txs.insert(topic, tx);
        rx
    }

    pub fn unsubscribe(&self, topic: u8) {
        self.txs.remove(&topic);
    }

    pub async fn send_request(&self, peer_id: PeerId, mut request: Vec<u8>, topic: u8) {
        request.push(topic);

        let mut swarm = self.swarm.lock().await;
        let _ = swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_request(&peer_id, request);
    }

    pub async fn send_response(
        &self,
        channel: ResponseChannel,
        mut response: Vec<u8>,
        topic: u8,
    ) -> Result<()> {
        response.push(topic);

        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_response(channel, response)
            .map_err(|_| Error::SendResponse)?;

        Ok(())
    }
}

impl<T> From<mpsc::error::SendError<T>> for Error {
    fn from(e: mpsc::error::SendError<T>) -> Self {
        Error::Send(e.to_string())
    }
}
