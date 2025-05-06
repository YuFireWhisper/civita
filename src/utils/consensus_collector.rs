use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use tokio::{sync::mpsc::Receiver as TokioReceiver, time::Duration as TokioDuration};

use crate::{crypto::threshold, network::transport::protocols::gossipsub, traits::Byteable};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Byteable(String),

    #[error("Already consensus with initial items")]
    AlreadyConsensus,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("{0}")]
    Validator(String),

    #[error("{0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

#[trait_variant::make(Send)]
pub trait Validator<T, E> {
    async fn validate(&mut self, message: gossipsub::Message) -> std::result::Result<Option<T>, E>;
}

pub struct ConsensusCollector<T, E, V>
where
    T: Byteable,
    E: Display,
    V: Validator<T, E>,
{
    validator: V,
    timeout: TokioDuration,
    expected_peers: Option<HashSet<libp2p::PeerId>>,
    threshold: Option<u16>,
    threshold_counter: threshold::Counter,
    collected: HashMap<[u8; 32], u16>,
    _marker: std::marker::PhantomData<(T, E)>,
}

impl<T, E, V> ConsensusCollector<T, E, V>
where
    T: Byteable,
    E: Display,
    V: Validator<T, E>,
{
    pub fn new(
        validator: V,
        timeout: TokioDuration,
        threshold_counter: threshold::Counter,
    ) -> Self {
        Self {
            validator,
            timeout,
            threshold_counter,
            threshold: None,
            expected_peers: None,
            collected: HashMap::new(),
            _marker: std::marker::PhantomData,
        }
    }

    pub fn with_expected_peers(mut self, expected_peers: HashSet<libp2p::PeerId>) -> Self {
        let threshold = self.threshold_counter.call(expected_peers.len() as u16);
        self.expected_peers = Some(expected_peers);
        self.threshold = Some(threshold);
        self
    }

    pub fn with_initial_item(mut self, item: &T, peer: libp2p::PeerId) -> Result<Self> {
        if !self.add_item(item, peer)? {
            return Err(Error::AlreadyConsensus);
        }

        Ok(self)
    }

    fn add_item(&mut self, item: &T, peer: libp2p::PeerId) -> Result<bool> {
        let hash = Self::hash_item(item)?;

        if let Some(peers) = self.expected_peers.as_mut() {
            peers.remove(&peer);
        }

        let count = self.collected.entry(hash).or_default();
        *count += 1;
        let count = *count;

        Ok(self.is_consensus(count))
    }

    fn hash_item(item: &T) -> Result<[u8; 32]> {
        item.to_vec()
            .map_err(|e| Error::Byteable(e.to_string()))
            .map(|bytes| *blake3::hash(&bytes).as_bytes())
    }

    fn is_consensus(&self, count: u16) -> bool {
        self.threshold.is_some_and(|threshold| count >= threshold)
    }

    pub async fn collect(
        &mut self,
        rx: &mut TokioReceiver<gossipsub::Message>,
    ) -> Result<Option<T>> {
        assert!(self.threshold.is_some(), "Threshold not set");
        assert!(self.expected_peers.is_some(), "Expected peers not set");

        match tokio::time::timeout(self.timeout, self.collect_internal(rx)).await {
            Ok(result) => result,
            Err(_timeout) => {
                self.expected_peers.take();
                Ok(None)
            }
        }
    }

    async fn collect_internal(
        &mut self,
        rx: &mut TokioReceiver<gossipsub::Message>,
    ) -> Result<Option<T>> {
        while let Some(msg) = rx.recv().await {
            if !self.is_valid_peer(&msg.source) {
                continue;
            }

            if let Some(item) = self.process_message(msg).await? {
                self.expected_peers.take();
                return Ok(Some(item));
            }
        }

        Err(Error::ChannelClosed)
    }

    fn is_valid_peer(&self, peer_id: &libp2p::PeerId) -> bool {
        if let Some(expected_peers) = &self.expected_peers {
            expected_peers.contains(peer_id)
        } else {
            true
        }
    }

    async fn process_message(&mut self, msg: gossipsub::Message) -> Result<Option<T>> {
        match self.validator.validate(msg.clone()).await {
            Ok(Some(item)) => {
                let consensus_reached = self.add_item(&item, msg.source)?;
                if consensus_reached {
                    Ok(Some(item))
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Validator(e.to_string())),
        }
    }

    pub async fn collect_one(
        &mut self,
        rx: &mut TokioReceiver<gossipsub::Message>,
        expected_peer: libp2p::PeerId,
    ) -> Result<Option<T>> {
        tokio::time::timeout(self.timeout, async {
            while let Some(msg) = rx.recv().await {
                if msg.source != expected_peer {
                    continue;
                }

                return self
                    .validator
                    .validate(msg)
                    .await
                    .map_err(|e| Error::Validator(e.to_string()));
            }

            Err(Error::ChannelClosed)
        })
        .await
        .map_err(Error::from)?
    }
}
