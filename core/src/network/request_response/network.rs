use std::sync::Arc;

use dashmap::DashMap;
use libp2p::{
    request_response::{OutboundFailure, OutboundRequestId, ResponseChannel},
    PeerId, Swarm,
};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::network::{
    behaviour::Behaviour,
    request_response::{Event, Message},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Failed to send response")]
    SendResponse,

    #[error("{0}")]
    Send(String),

    #[error("Timeout while waiting for response")]
    Timeout,

    #[error(transparent)]
    OutboundFailure(#[from] OutboundFailure),

    #[error("Channel closed")]
    ChannelClosed,
}

enum ReqeustResult {
    GotResponse(Vec<u8>),
    Failed(OutboundFailure),
}

pub struct RequestResponse {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    tx: mpsc::Sender<Message>,

    waiting_resp: DashMap<OutboundRequestId, oneshot::Sender<ReqeustResult>>,
}

impl RequestResponse {
    pub fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>, tx: mpsc::Sender<Message>) -> Self {
        Self {
            swarm,
            tx,
            waiting_resp: DashMap::new(),
        }
    }

    pub async fn handle_event(&self, event: Event) -> Result<()> {
        match event {
            Event::Message { message, .. } => match message {
                Message::Request { .. } => {
                    self.tx.send(message).await?;
                }
                Message::Response {
                    response,
                    request_id,
                } => {
                    if let Some(tx) = self.waiting_resp.remove(&request_id) {
                        let _ = tx.1.send(ReqeustResult::GotResponse(response));
                    }
                }
            },
            Event::OutboundFailure {
                request_id, error, ..
            } => {
                if let Some(tx) = self.waiting_resp.remove(&request_id) {
                    let _ = tx.1.send(ReqeustResult::Failed(error));
                }
            }
            _ => {}
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

    pub async fn send_request_and_wait(
        &self,
        peer_id: PeerId,
        request: Vec<u8>,
        timeout: tokio::time::Duration,
    ) -> Result<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        let mut swarm = self.swarm.lock().await;
        let id = swarm
            .behaviour_mut()
            .req_resp_mut()
            .send_request(&peer_id, request);

        self.waiting_resp.insert(id, tx);

        tokio::select! {
            res = rx => match res {
                Ok(ReqeustResult::GotResponse(response)) => Ok(response),
                Ok(ReqeustResult::Failed(error)) => Err(Error::OutboundFailure(error)),
                Err(_) => Err(Error::ChannelClosed),
            },
            _ = tokio::time::sleep(timeout) => Err(Error::Timeout),
        }
    }
}

impl<T> From<mpsc::error::SendError<T>> for Error {
    fn from(e: mpsc::error::SendError<T>) -> Self {
        Error::Send(e.to_string())
    }
}
