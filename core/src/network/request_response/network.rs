use std::sync::Arc;

use libp2p::{
    request_response::{self, ResponseChannel},
    PeerId, Swarm,
};
use tokio::sync::{mpsc, Mutex};

use crate::network::{behaviour::Behaviour, request_response::Event};

type Result<T, E = Error> = std::result::Result<T, E>;
type Message = request_response::Message<Vec<u8>, Vec<u8>>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to send response")]
    SendResponse,

    #[error("{0}")]
    SendError(String),
}

pub struct RequestResponse {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    tx: Option<mpsc::Sender<Message>>,
}

impl RequestResponse {
    pub fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>) -> Self {
        Self { swarm, tx: None }
    }

    pub async fn handle_event(&self, event: Event) -> Result<()> {
        if let Event::Message { message, .. } = event {
            if let Some(tx) = &self.tx {
                tx.send(message).await?;
            }
        }

        Ok(())
    }

    pub async fn send_request(&self, peer_id: PeerId, request: Vec<u8>) -> Result<()> {
        let mut swarm = self.swarm.lock().await;
        let _ = swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_request(&peer_id, request);
        Ok(())
    }

    pub async fn send_response(
        &self,
        ch: ResponseChannel<Vec<u8>>,
        response: Vec<u8>,
    ) -> Result<()> {
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_response(ch, response)
            .map_err(|_| Error::SendResponse)?;
        Ok(())
    }
}

impl From<mpsc::error::SendError<Message>> for Error {
    fn from(e: mpsc::error::SendError<Message>) -> Self {
        Error::SendError(e.to_string())
    }
}
