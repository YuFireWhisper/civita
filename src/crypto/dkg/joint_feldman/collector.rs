use crate::{
    crypto::primitives::{
        algebra::element::{Public, Secret},
        threshold,
        vss::Vss,
    },
    network::transport::libp2p_transport::protocols::{
        gossipsub,
        request_response::{self, payload::Request},
    },
};
use std::{collections::HashMap, marker::PhantomData};
use thiserror::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Collection timed out")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Recv error: {0}")]
    Recv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Validation failed for peer {0}")]
    ValidationFailed(libp2p::PeerId),

    #[error("Send error: {0}")]
    Send(String),

    #[error("Duplicate query")]
    DuplicateQuery,
}

struct PartialPair<SK: Secret, PK: Public> {
    share: Option<SK>,
    commitments: Option<Vec<PK>>,
}

#[derive(Clone)]
pub struct CompletePair<SK: Secret, PK: Public> {
    pub share: SK,
    pub commitments: Vec<PK>,
    pub peer: libp2p::PeerId,
}

#[derive(Clone)]
pub struct CollectionResult<SK: Secret, PK: Public> {
    pub shares: Vec<SK>,
    pub commitments: Vec<Vec<PK>>,
    pub participants: Vec<libp2p::PeerId>,
}

pub struct CollectionContext<SK: Secret, PK: Public, V: Vss<SK, PK>> {
    pending: HashMap<u16, PartialPair<SK, PK>>,
    collected: Vec<CompletePair<SK, PK>>,
    required: usize,
    index_map: HashMap<libp2p::PeerId, u16>,
    own_index: u16,
    _marker: PhantomData<V>,
}

impl<SK: Secret, PK: Public, V: Vss<SK, PK>> CollectionContext<SK, PK, V> {
    pub fn new(threshold: u16, peers: &[libp2p::PeerId], own_peer: libp2p::PeerId) -> Self {
        let index_map: HashMap<libp2p::PeerId, u16> = peers
            .iter()
            .enumerate()
            .map(|(i, p)| (*p, (i + 1) as u16))
            .collect();
        let own_index = *index_map
            .get(&own_peer)
            .expect("Own peer not found in index map");

        Self {
            pending: HashMap::with_capacity(threshold as usize),
            collected: Vec::with_capacity(threshold as usize),
            required: threshold as usize,
            index_map,
            own_index,
            _marker: PhantomData,
        }
    }

    pub fn add_share(
        &mut self,
        peer: libp2p::PeerId,
        share: SK,
    ) -> Option<CollectionResult<SK, PK>> {
        if self.index_map.contains_key(&peer) {
            self.insert(Some(share), None, peer)
        } else {
            None
        }
    }

    pub fn add_commitments(
        &mut self,
        peer: libp2p::PeerId,
        commitments: Vec<PK>,
    ) -> Option<CollectionResult<SK, PK>> {
        if self.index_map.contains_key(&peer) {
            self.insert(None, Some(commitments), peer)
        } else {
            None
        }
    }

    fn insert(
        &mut self,
        share: Option<SK>,
        commitments: Option<Vec<PK>>,
        peer: libp2p::PeerId,
    ) -> Option<CollectionResult<SK, PK>> {
        let index = self
            .index_map
            .get(&peer)
            .copied()
            .expect("Peer not found in index map");
        let entry = self.pending.entry(index).or_default();
        if let Some(s) = share {
            entry.share = Some(s);
        }
        if let Some(c) = commitments {
            entry.commitments = Some(c);
        }

        if let (Some(s), Some(c)) = (entry.share.take(), entry.commitments.take()) {
            self.pending.remove(&index);
            if let Some(valid) = CompletePair::verify::<V>(self.own_index, s, c, peer) {
                self.collected.push(valid);
            } else {
                self.index_map.remove(&peer);
            }
        }

        if self.collected.len() >= self.required {
            let collected = std::mem::take(&mut self.collected);

            let shares = collected.iter().map(|pair| pair.share.clone()).collect();
            let commitments = collected
                .iter()
                .map(|pair| pair.commitments.clone())
                .collect();
            let participants = collected.iter().map(|pair| pair.peer).collect();

            Some(CollectionResult {
                shares,
                commitments,
                participants,
            })
        } else {
            None
        }
    }

    pub fn is_peer_valid(&self, peer: &libp2p::PeerId) -> bool {
        self.index_map.contains_key(peer)
    }
}

impl<SK: Secret, PK: Public> CompletePair<SK, PK> {
    pub fn verify<V: Vss<SK, PK>>(
        index: u16,
        share: SK,
        commitments: Vec<PK>,
        peer: libp2p::PeerId,
    ) -> Option<Self> {
        V::verify(&index, &share, &commitments).then(|| Self {
            share,
            commitments,
            peer,
        })
    }
}

type QuerySender<SK, PK> = tokio::sync::mpsc::Sender<(
    Vec<u8>,
    tokio::sync::oneshot::Sender<Option<CollectionResult<SK, PK>>>,
)>;

pub struct Collector<SK, PK, V>
where
    SK: Secret,
    PK: Public,
    V: Vss<SK, PK>,
{
    own_peer: libp2p::PeerId,
    timeout: tokio::time::Duration,
    threshold_counter: threshold::Counter,
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
        threshold_counter: threshold::Counter,
    ) -> Self {
        Self {
            own_peer: id,
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
        peers: Vec<libp2p::PeerId>,
    ) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        self.query_sender = Some(tx);

        let threshold = self.threshold_counter.call(peers.len() as u16);
        let own_peer = self.own_peer;

        let handle = tokio::spawn(async move {
            let mut contexts = HashMap::<Vec<u8>, CollectionContext<SK, PK, V>>::new();
            let mut done = HashMap::<Vec<u8>, CollectionResult<SK, PK>>::new();
            let mut queries = HashMap::<
                Vec<u8>,
                tokio::sync::oneshot::Sender<Option<CollectionResult<SK, PK>>>,
            >::new();
            let mut queried_ids = std::collections::HashSet::<Vec<u8>>::new();

            loop {
                tokio::select! {
                    Some(msg) = request_rx.recv() => {
                        if let request_response::Payload::Request(Request::VSSShare { id, share }) = msg.payload {
                            if queried_ids.contains(&id) {
                                continue;
                            }

                            let ctx = contexts
                                .entry(id.clone())
                                .or_insert_with(|| CollectionContext::new(threshold, &peers, own_peer));

                            if !ctx.is_peer_valid(&msg.peer) {
                                continue;
                            }

                            let share = SK::from_bytes(&share);

                            if let Some(result) = ctx.add_share(msg.peer, share) {
                                contexts.remove(&id);
                                if let Some(tx) = queries.remove(&id) {
                                    let _ = tx.send(Some(result));
                                    queried_ids.insert(id);
                                } else {
                                    done.insert(id, result);
                                }
                            }
                        }
                    }
                    Some(msg) = gossipsub_rx.recv() => {
                        if let gossipsub::Payload::VSSCommitments { id, commitments } = msg.payload {
                            if queried_ids.contains(&id) {
                                continue;
                            }

                            let ctx = contexts
                                .entry(id.clone())
                                .or_insert_with(|| CollectionContext::new(threshold, &peers, own_peer));

                            if !ctx.is_peer_valid(&msg.source) {
                                continue;
                            }

                            let commitments = commitments
                                .iter()
                                .map(|c| PK::from_bytes(c))
                                .collect::<Vec<_>>();

                            if let Some(result) = ctx.add_commitments(msg.source, commitments) {
                                contexts.remove(&id);
                                if let Some(tx) = queries.remove(&id) {
                                    let _ = tx.send(Some(result));
                                    queried_ids.insert(id);
                                } else {
                                    done.insert(id, result);
                                }
                            }
                        }
                    }
                    Some((id, responder)) = rx.recv() => {
                        if queried_ids.contains(&id) {
                            let _ = responder.send(None);
                        } else if let Some(result) = done.remove(&id) {
                            let _ = responder.send(Some(result));
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

    pub async fn query(&self, request_id: Vec<u8>) -> Result<CollectionResult<SK, PK>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sender = self.query_sender.as_ref().expect("Collector not started");
        sender
            .send((request_id.clone(), tx))
            .await
            .map_err(|e| Error::Send(e.to_string()))?;
        tokio::time::timeout(self.timeout, rx)
            .await??
            .ok_or(Error::DuplicateQuery)
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
