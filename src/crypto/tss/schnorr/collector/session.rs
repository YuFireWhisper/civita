use std::collections::{HashMap, HashSet};

use tokio::sync::oneshot::Sender as TokioOneShotSender;

use crate::crypto::{
    primitives::algebra::{Point, Scalar},
    tss::schnorr::collector::CollectionResult,
};

#[derive(Debug)]
pub struct Session {
    shares: HashMap<libp2p::PeerId, Scalar>,
    pending_peers: HashSet<libp2p::PeerId>,
    invalid_peers: HashSet<libp2p::PeerId>,
    global_comms: Vec<Point>,
    completed: bool,
    threshold: u16,
    callback: Option<TokioOneShotSender<CollectionResult>>,
}

impl Session {
    pub fn new(
        peers: impl Iterator<Item = libp2p::PeerId>,
        global_comms: Vec<Point>,
        threshold: u16,
    ) -> Self {
        Self {
            shares: HashMap::new(),
            pending_peers: peers.collect(),
            invalid_peers: HashSet::new(),
            global_comms,
            completed: false,
            threshold,
            callback: None,
        }
    }

    pub fn add_share(&mut self, peer_id: libp2p::PeerId, peer_index: u16, share: Scalar) {
        if self.completed || self.invalid_peers.contains(&peer_id) {
            return;
        }

        if self.pending_peers.remove(&peer_id) {
            if !self.verify_share(peer_index, &share) {
                self.invalid_peers.insert(peer_id);
                log::warn!("Invalid nonce share from peer: {:?}", peer_id);
            } else {
                self.shares.insert(peer_id, share);
                self.try_complete();
            }
        }
    }

    fn verify_share(&self, peer_index: u16, share: &Scalar) -> bool {
        share.verify(peer_index, &self.global_comms).is_ok()
    }

    fn try_complete(&mut self) {
        if !self.has_threshold_reached() || self.completed {
            return;
        }

        if let Some(callback) = self.callback.take() {
            let output = CollectionResult::Success(self.shares.to_owned());
            if let Err(e) = callback.send(output) {
                log::warn!("Failed to send nonce shares: {:?}", e);
            }
            self.completed = true;
        }
    }

    fn has_threshold_reached(&self) -> bool {
        self.shares.len() >= self.threshold as usize
    }

    pub fn set_callback(&mut self, callback: TokioOneShotSender<CollectionResult>) {
        if self.completed {
            return;
        }

        self.callback = Some(callback);
        self.try_complete();
    }

    pub fn is_completed(&self) -> bool {
        self.completed
    }

    pub fn force_completion(&mut self, callback: TokioOneShotSender<CollectionResult>) {
        if self.completed {
            return;
        }

        if self.has_threshold_reached() {
            let result = CollectionResult::Success(self.shares.clone());
            if let Err(e) = callback.send(result) {
                log::warn!("Failed to send collection result: {:?}", e);
            }
        } else {
            self.invalid_peers.extend(self.pending_peers.iter());
            let result = CollectionResult::Failure(self.invalid_peers.clone());
            if let Err(e) = callback.send(result) {
                log::warn!("Failed to send collection result: {:?}", e);
            }
        }

        self.completed = true;
    }
}
