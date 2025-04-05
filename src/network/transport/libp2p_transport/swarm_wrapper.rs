use futures::StreamExt;
use libp2p::{
    gossipsub::{IdentTopic, MessageId, PublishError, SubscriptionError},
    kad::{store, Quorum, Record},
    swarm::{DialError, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    oneshot,
};

use crate::network::transport::libp2p_transport::{
    behaviour::{Behaviour, Event},
    protocols::request_response::payload::Request,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Publish error: {0}")]
    Publish(#[from] PublishError),

    #[error("Failed to send action: {0}")]
    SendAction(String),

    #[error("Response channel closed")]
    ResponseChannelClosed,

    #[error("Dial error: {0}")]
    Dial(#[from] DialError),

    #[error("Subscription error: {0}")]
    Subscribe(#[from] SubscriptionError),

    #[error("Store error: {0}")]
    Store(#[from] store::Error),

    #[error("Swarm event channel closed")]
    EventChannelClosed,
}

#[derive(Debug)]
pub enum Action {
    Dial(PeerId, Multiaddr),

    Subscribe(IdentTopic),

    Publish(IdentTopic, Vec<u8>),

    Request(PeerId, Request),

    Put(Record, Quorum),
}

#[derive(Debug)]
pub enum ActionResult {
    Publish(MessageId),

    NoResult,
}

struct ActionWithResponseChannel {
    action: Action,
    response_tx: oneshot::Sender<Result<ActionResult>>,
}

pub struct SwarmWrapper {
    swarm: Arc<tokio::sync::Mutex<Swarm<Behaviour>>>,
    action_tx: Sender<ActionWithResponseChannel>,
    event_tx: Sender<Event>,
}

impl SwarmWrapper {
    pub fn new(swarm: Swarm<Behaviour>, event_tx: Sender<Event>, channel_size: usize) -> Self {
        let (action_tx, action_rx) = mpsc::channel(channel_size);
        let swarm = Arc::new(tokio::sync::Mutex::new(swarm));

        let wrapper = Self {
            swarm: swarm.clone(),
            action_tx,
            event_tx: event_tx.clone(),
        };

        tokio::spawn(Self::run_event_loop(swarm, action_rx, event_tx));

        wrapper
    }

    async fn run_event_loop(
        swarm: Arc<tokio::sync::Mutex<Swarm<Behaviour>>>,
        mut action_rx: Receiver<ActionWithResponseChannel>,
        event_tx: Sender<Event>,
    ) {
        loop {
            let mut swarm_lock = swarm.lock().await;

            tokio::select! {
                Some(action_with_channel) = action_rx.recv() => {
                    let ActionWithResponseChannel { action, response_tx } = action_with_channel;
                    let result = Self::handle_action(&mut swarm_lock, action).await;

                    let _ = response_tx.send(result);
                }

                event = swarm_lock.select_next_some() => {
                    if let SwarmEvent::Behaviour(event) = event {
                        if let Err(e) = event_tx.send(event).await {
                            log::error!("Failed to send event: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_action(swarm: &mut Swarm<Behaviour>, action: Action) -> Result<ActionResult> {
        match action {
            Action::Dial(peer_id, addr) => {
                swarm
                    .behaviour_mut()
                    .kad_mut()
                    .add_address(&peer_id, addr.clone());
                swarm.add_peer_address(peer_id, addr.clone());
                swarm.dial(addr)?;
                Ok(ActionResult::NoResult)
            }

            Action::Subscribe(topic) => {
                swarm.behaviour_mut().gossipsub_mut().subscribe(&topic)?;
                Ok(ActionResult::NoResult)
            }

            Action::Publish(topic, data) => {
                let msg_id = swarm.behaviour_mut().gossipsub_mut().publish(topic, data)?;
                Ok(ActionResult::Publish(msg_id))
            }

            Action::Request(peer_id, request) => {
                swarm
                    .behaviour_mut()
                    .request_response_mut()
                    .send_request(&peer_id, request);
                Ok(ActionResult::NoResult)
            }

            Action::Put(record, quorum) => {
                swarm.behaviour_mut().kad_mut().put_record(record, quorum)?;
                Ok(ActionResult::NoResult)
            }
        }
    }

    pub async fn send_action(&self, action: Action) -> Result<ActionResult> {
        let (response_tx, response_rx) = oneshot::channel();

        self.action_tx
            .send(ActionWithResponseChannel {
                action,
                response_tx,
            })
            .await
            .map_err(|e| Error::SendAction(e.to_string()))?;

        response_rx
            .await
            .map_err(|_| Error::ResponseChannelClosed)?
    }
}
