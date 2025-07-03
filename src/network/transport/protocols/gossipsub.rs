use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use libp2p::{
    gossipsub::{Event, IdentTopic, TopicHash},
    PeerId, Swarm,
};
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::{
    crypto::Multihash,
    network::{
        traits::{self, gossipsub::Error},
        transport::behaviour::Behaviour,
    },
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct Config {
    pub timeout: tokio::time::Duration,
    pub channel_size: usize,
}

#[derive(Debug)]
#[derive(Default)]
pub struct ConfigBuilder {
    timeout: Option<tokio::time::Duration>,
    channel_size: Option<usize>,
}

pub struct Gossipsub {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    local_peer_id: PeerId,
    subscribed: DashMap<TopicHash, mpsc::Sender<Vec<u8>>>,
    subscribed_peer: DashMap<TopicHash, HashSet<Multihash>>,
    waiting_subscription: DashMap<TopicHash, oneshot::Sender<()>>,
    config: Config,
}

impl ConfigBuilder {
    const DEFAULT_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(10);
    const DEFAULT_CHANNEL_SIZE: usize = 1000;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: tokio::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_channel_size(mut self, size: usize) -> Self {
        self.channel_size = Some(size);
        self
    }

    pub fn build(self) -> Config {
        let waiting_subscription_timeout = self.timeout.unwrap_or(Self::DEFAULT_TIMEOUT);
        let channel_size = self.channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE);

        Config {
            timeout: waiting_subscription_timeout,
            channel_size,
        }
    }
}

impl Gossipsub {
    pub async fn new(swarm: Arc<Mutex<Swarm<Behaviour>>>, peer_id: PeerId, config: Config) -> Self {
        Self {
            swarm,
            local_peer_id: peer_id,
            subscribed: DashMap::new(),
            subscribed_peer: DashMap::new(),
            waiting_subscription: DashMap::new(),
            config,
        }
    }

    pub async fn handle_event(&self, event: Event) -> Result<()> {
        match event {
            Event::Subscribed { topic, peer_id } => {
                if let Some((_, tx)) = self.waiting_subscription.remove(&topic) {
                    let _ = tx.send(());
                }

                self.subscribed_peer
                    .entry(topic)
                    .or_default()
                    .insert(peer_id.as_ref().to_owned());
            }

            Event::Unsubscribed { topic, peer_id } => {
                if peer_id == self.local_peer_id {
                    self.subscribed.remove(&topic);
                }

                if let Some(mut peers) = self.subscribed_peer.get_mut(&topic) {
                    peers.remove(&peer_id.as_ref().to_owned());

                    if peers.is_empty() {
                        drop(peers);
                        self.subscribed_peer.remove(&topic);
                    }
                }
            }

            Event::Message { message, .. } => {
                if let Some(tx) = self.subscribed.get(&message.topic) {
                    if let Err(e) = tx.send(message.data).await {
                        log::warn!("Failed to send message to subscriber: {e}");
                    }
                }
            }

            _ => {}
        }

        Ok(())
    }

    pub async fn subscribe(&self, topic: u8) -> Result<mpsc::Receiver<Vec<u8>>> {
        let topic = IdentTopic::new(topic.to_string());

        self.swarm
            .lock()
            .await
            .behaviour_mut()
            .gossipsub_mut()
            .subscribe(&topic)?;

        let (tx, rx) = mpsc::channel(self.config.channel_size);

        self.subscribed.insert(topic.hash(), tx);
        self.subscribed_peer
            .entry(topic.hash())
            .or_default()
            .insert(*self.local_peer_id.as_ref());

        Ok(rx)
    }

    pub async fn unsubscribe(&self, topic: u8) -> Result<()> {
        let topic = IdentTopic::new(topic.to_string());

        if !self
            .swarm
            .lock()
            .await
            .behaviour_mut()
            .gossipsub_mut()
            .unsubscribe(&topic)
        {
            // We are not subscribed to this topic, nothing to do
            return Ok(());
        }

        self.subscribed.remove(&topic.hash());

        if let Some(mut peers) = self.subscribed_peer.get_mut(&topic.hash()) {
            peers.remove(self.local_peer_id.as_ref());

            if peers.is_empty() {
                drop(peers);
                self.subscribed_peer.remove(&topic.hash());
            }
        }

        Ok(())
    }

    pub async fn publish(&self, topic: u8, data: Vec<u8>) -> Result<()> {
        let topic = IdentTopic::new(topic.to_string());

        if !self.subscribed_peer.contains_key(&topic.hash()) {
            let (tx, rx) = oneshot::channel();
            self.waiting_subscription.insert(topic.hash(), tx);

            tokio::time::timeout(self.config.timeout, rx)
                .await
                .expect("Timeout waiting for subscription")
                .expect("Failed to receive subscription confirmation");
        }

        self.swarm
            .lock()
            .await
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, data)?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl traits::Gossipsub for Arc<Gossipsub> {
    async fn subscribe(&self, topic: u8) -> Result<mpsc::Receiver<Vec<u8>>> {
        self.subscribe(topic).await
    }

    async fn unsubscribe(&self, topic: u8) -> Result<()> {
        self.unsubscribe(topic).await
    }

    async fn publish(&self, topic: u8, data: Vec<u8>) -> Result<()> {
        self.publish(topic, data).await
    }
}
