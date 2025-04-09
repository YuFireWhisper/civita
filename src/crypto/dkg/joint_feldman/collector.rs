use crate::{
    crypto::{
        core::threshold_counter::ThresholdCounter,
        primitives::{
            algebra::element::{Public, Secret},
            vss::Vss,
        },
    },
    network::transport::libp2p_transport::protocols::{
        gossipsub,
        request_response::{self, payload::Request},
    },
};
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Collection timed out")]
    Timeout,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Validation failed for peer {0}")]
    ValidationFailed(libp2p::PeerId),

    #[error("Send error: {0}")]
    Send(String),
}

struct PartialPair<SK: Secret, PK: Public> {
    share: Option<SK>,
    commitments: Option<Vec<PK>>,
}

#[derive(Clone)]
pub struct CompletePair<SK: Secret, PK: Public> {
    pub share: SK,
    pub commitments: Vec<PK>,
}

impl<SK: Secret, PK: Public> CompletePair<SK, PK> {
    pub fn verify<V: Vss<SK, PK>>(index: u16, share: SK, commitments: Vec<PK>) -> Option<Self> {
        V::verify(&index, &share, &commitments).then(|| Self { share, commitments })
    }
}

struct PairManager<SK: Secret, PK: Public, V: Vss<SK, PK>> {
    pending: HashMap<u16, PartialPair<SK, PK>>,
    collected: Vec<CompletePair<SK, PK>>,
    required: usize,
    _marker: PhantomData<V>,
}

impl<SK: Secret, PK: Public, V: Vss<SK, PK>> PairManager<SK, PK, V> {
    pub fn with_threshold(threshold: u16) -> Self {
        Self {
            pending: HashMap::with_capacity(threshold as usize),
            collected: Vec::with_capacity(threshold as usize),
            required: threshold as usize,
            _marker: PhantomData,
        }
    }

    pub fn add_share(&mut self, index: u16, share: SK) -> Option<Vec<CompletePair<SK, PK>>> {
        self.insert(index, Some(share), None)
    }

    pub fn add_commitments(
        &mut self,
        index: u16,
        commitments: Vec<PK>,
    ) -> Option<Vec<CompletePair<SK, PK>>> {
        self.insert(index, None, Some(commitments))
    }

    fn insert(
        &mut self,
        index: u16,
        share: Option<SK>,
        commitments: Option<Vec<PK>>,
    ) -> Option<Vec<CompletePair<SK, PK>>> {
        let entry = self.pending.entry(index).or_default();
        if let Some(s) = share {
            entry.share = Some(s);
        }
        if let Some(c) = commitments {
            entry.commitments = Some(c);
        }

        if let (Some(s), Some(c)) = (entry.share.take(), entry.commitments.take()) {
            self.pending.remove(&index);
            if let Some(valid) = CompletePair::verify::<V>(index, s, c) {
                self.collected.push(valid);
            }
        }

        if self.collected.len() >= self.required {
            Some(std::mem::take(&mut self.collected))
        } else {
            None
        }
    }
}

type QuerySender<SK, PK> = tokio::sync::mpsc::Sender<(
    Vec<u8>,
    tokio::sync::oneshot::Sender<Vec<CompletePair<SK, PK>>>,
)>;

pub struct Collector<SK, PK, V>
where
    SK: Secret,
    PK: Public,
    V: Vss<SK, PK>,
{
    id: libp2p::PeerId,
    timeout: tokio::time::Duration,
    threshold_counter: ThresholdCounter,
    handle: Option<tokio::task::JoinHandle<()>>,
    query_sender: Option<QuerySender<SK, PK>>,
    _marker: PhantomData<V>,
}

impl<SK, PK, V> Collector<SK, PK, V>
where
    SK: Secret + 'static,
    PK: Public + 'static,
    V: Vss<SK, PK> + 'static,
{
    pub fn new(
        id: libp2p::PeerId,
        timeout: tokio::time::Duration,
        threshold_counter: ThresholdCounter,
    ) -> Self {
        Self {
            id,
            timeout,
            threshold_counter,
            handle: None,
            query_sender: None,
            _marker: PhantomData,
        }
    }

    pub fn start(
        &mut self,
        mut gossipsub_rx: tokio::sync::mpsc::Receiver<gossipsub::Message>,
        mut request_rx: tokio::sync::mpsc::Receiver<request_response::Message>,
        peers: &[libp2p::PeerId],
    ) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        self.query_sender = Some(tx);

        let threshold = self.threshold_counter.call(peers.len() as u16);
        let index_map: HashMap<libp2p::PeerId, u16> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, (i + 1) as u16))
            .collect();
        let own_index = *index_map
            .get(&self.id)
            .expect("Self peer not found in peers list");

        let handle = tokio::spawn(async move {
            let mut pending = HashMap::<Vec<u8>, PairManager<SK, PK, V>>::new();
            let mut done = HashMap::<Vec<u8>, Vec<CompletePair<SK, PK>>>::new();
            let mut queries =
                HashMap::<Vec<u8>, tokio::sync::oneshot::Sender<Vec<CompletePair<SK, PK>>>>::new();

            loop {
                tokio::select! {
                    Some(msg) = request_rx.recv() => {
                        if let request_response::Payload::Request(Request::VSSShare { id, share }) = msg.payload {
                            if !index_map.contains_key(&msg.peer) || done.contains_key(&id) {
                                continue;
                            }
                            let share = SK::from_bytes(&share);
                            let manager = pending.entry(id.clone())
                                .or_insert_with(|| PairManager::with_threshold(threshold));
                            if let Some(pairs) = manager.add_share(own_index, share) {
                                pending.remove(&id);
                                if let Some(tx) = queries.remove(&id) {
                                    let _ = tx.send(pairs.clone());
                                } else {
                                    log::warn!("No query for id: {:?}", id);
                                }
                                done.insert(id, pairs);
                            }
                        }
                    }
                    Some(msg) = gossipsub_rx.recv() => {
                        if let gossipsub::Payload::VSSCommitments { id, commitments } = msg.payload {
                            if !index_map.contains_key(&msg.source) || done.contains_key(&id) {
                                continue;
                            }
                            let commitments = commitments.iter()
                                .map(|b| PK::from_bytes(b)).collect::<Vec<_>>();
                            let manager = pending.entry(id.clone())
                                .or_insert_with(|| PairManager::with_threshold(threshold));
                            if let Some(pairs) = manager.add_commitments(index_map[&msg.source], commitments) {
                                pending.remove(&id);
                                if let Some(tx) = queries.remove(&id) {
                                    let _ = tx.send(pairs.clone());
                                } else {
                                    log::warn!("No query for id: {:?}", id);
                                }
                                done.insert(id, pairs);
                            }
                        }
                    }
                    Some((id, responder)) = rx.recv() => {
                        if let Some(results) = done.get_mut(&id) {
                            let mut batch = Vec::with_capacity(results.len());
                            std::mem::swap(results, &mut batch);
                            let _ = responder.send(batch);
                        } else {
                            queries.insert(id, responder);
                        }
                    }
                    else => break,
                }
            }
        });

        self.handle = Some(handle);
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
        self.query_sender = None;
    }

    pub async fn query(&self, request_id: Vec<u8>) -> Result<Vec<CompletePair<SK, PK>>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sender = self.query_sender.as_ref().expect("Collector not started");
        sender
            .send((request_id.clone(), tx))
            .await
            .map_err(|e| Error::Send(e.to_string()))?;
        tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::ChannelClosed)
    }
}

impl<SK, PK> Default for PartialPair<SK, PK>
where
    SK: Secret,
    PK: Public,
{
    fn default() -> Self {
        Self {
            share: None,
            commitments: None,
        }
    }
}
