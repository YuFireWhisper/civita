use std::sync::Arc;

use libp2p::{
    gossipsub::{Event, MessageAcceptance, MessageId},
    PeerId, Swarm,
};
use tokio::sync::{mpsc, Mutex};

use crate::network::behaviour::Behaviour;

mod network;

pub use network::Config as NetworkConfig;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Network(#[from] network::Error),
}

pub struct Message {
    pub id: MessageId,
    pub propagation_source: PeerId,
    pub data: Vec<u8>,
}

pub enum Gossipsub {
    Network(network::Gossipsub),
}

impl Gossipsub {
    pub async fn new_network(
        swarm: Arc<Mutex<Swarm<Behaviour>>>,
        peer_id: PeerId,
        config: network::Config,
    ) -> Self {
        Gossipsub::Network(network::Gossipsub::new(swarm, peer_id, config).await)
    }

    pub(crate) async fn handle_event(&self, event: Event) -> Result<()> {
        match self {
            Gossipsub::Network(gossipsub) => {
                gossipsub.handle_event(event).await.map_err(Error::from)
            }
        }
    }

    pub async fn subscribe(&self, topic: u8) -> Result<mpsc::Receiver<Message>> {
        match self {
            Gossipsub::Network(gossipsub) => gossipsub.subscribe(topic).await.map_err(Error::from),
        }
    }

    pub async fn unsubscribe(&self, topic: u8) -> Result<()> {
        match self {
            Gossipsub::Network(gossipsub) => {
                gossipsub.unsubscribe(topic).await.map_err(Error::from)
            }
        }
    }

    pub async fn publish(&self, topic: u8, data: Vec<u8>) -> Result<()> {
        match self {
            Gossipsub::Network(gossipsub) => {
                gossipsub.publish(topic, data).await.map_err(Error::from)
            }
        }
    }

    pub async fn report_validation_result(
        &self,
        msg_id: &MessageId,
        propagation_source: &PeerId,
        acceptance: MessageAcceptance,
    ) {
        match self {
            Gossipsub::Network(gossipsub) => {
                gossipsub
                    .report_validation_result(msg_id, propagation_source, acceptance)
                    .await;
            }
        }
    }
}
