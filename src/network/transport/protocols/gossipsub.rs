use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;
use libp2p::{
    gossipsub::{IdentTopic, TopicHash},
    Swarm,
};

use crate::{
    network::transport::{behaviour::Behaviour, protocols::gossipsub::dispatcher::Dispatcher},
    traits::serializable::{self, Serializable},
};

mod dispatcher;
pub mod message;
pub mod payload;

pub use message::Message;
pub use payload::Payload;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Dispatch(#[from] dispatcher::Error),

    #[error("Subscribe error: {0}")]
    Subscribe(#[from] libp2p::gossipsub::SubscriptionError),

    #[error("No peer subscription to: {0}")]
    NoPeerSubscribed(String),

    #[error("Publish error: {0}")]
    Publish(#[from] libp2p::gossipsub::PublishError),

    #[error("Oneshot error: {0}")]
    Oneshot(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("{0}")]
    Serializable(#[from] serializable::Error),
}

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
    swarm: Arc<tokio::sync::Mutex<Swarm<Behaviour>>>,
    dispatcher: Dispatcher,
    subscribed_topics: Arc<tokio::sync::RwLock<HashSet<TopicHash>>>,
    waiting_subscription: DashMap<TopicHash, tokio::sync::oneshot::Sender<()>>,
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
    pub fn new(swarm: Arc<tokio::sync::Mutex<Swarm<Behaviour>>>, config: Config) -> Self {
        Self {
            swarm,
            dispatcher: Dispatcher::new(),
            subscribed_topics: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
            waiting_subscription: DashMap::new(),
            config,
        }
    }

    pub async fn handle_event(&self, event: libp2p::gossipsub::Event) -> Result<()> {
        match event {
            libp2p::gossipsub::Event::Subscribed { topic, .. } => {
                if let Some((_, tx)) = self.waiting_subscription.remove(&topic) {
                    let _ = tx.send(());
                }

                self.subscribed_topics.write().await.insert(topic);
            }
            event => match Message::try_from_gossipsub_event(event) {
                Ok(message) => {
                    self.dispatcher.dispatch(message)?;
                }
                Err(_) => {
                    log::warn!("Failed to convert event to message");
                }
            },
        }

        self.dispatcher.remove_dead();

        Ok(())
    }

    pub async fn subscribe(
        &self,
        topic: impl Into<String>,
    ) -> Result<tokio::sync::mpsc::Receiver<Message>> {
        let topic = IdentTopic::new(topic);

        self.swarm
            .lock()
            .await
            .behaviour_mut()
            .gossipsub_mut()
            .subscribe(&topic)
            .map_err(Error::Subscribe)?;

        let (tx, rx) = tokio::sync::mpsc::channel(self.config.channel_size);
        self.dispatcher.register(topic.to_string(), None, tx);

        Ok(rx)
    }

    pub async fn publish(
        &self,
        topic: impl Into<String>,
        payload: impl Into<Payload>,
    ) -> Result<libp2p::gossipsub::MessageId> {
        let topic = IdentTopic::new(topic);

        if !self.subscribed_topics.read().await.contains(&topic.hash()) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.waiting_subscription.insert(topic.hash(), tx);

            tokio::time::timeout(self.config.timeout, rx)
                .await
                .map_err(|_| Error::NoPeerSubscribed(topic.to_string()))??;
        }

        let payload = payload.into();

        self.swarm
            .lock()
            .await
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, payload.to_vec()?)
            .map_err(Error::from)
    }
}
