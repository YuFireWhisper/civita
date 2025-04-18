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

#[cfg(test)]
mod tests {
    use crate::crypto::{
        index_map::IndexedMap,
        primitives::{
            algebra::{Point, Scalar, Scheme},
            vss::Vss,
        },
        tss::schnorr::collector::{session::Session, CollectionResult},
    };

    const SCHEME: Scheme = Scheme::Secp256k1;
    const NUM_PEERS: u16 = 3;

    fn setup(n: u16) -> (IndexedMap<libp2p::PeerId, Scalar>, Vec<Point>, u16) {
        let mut peers = IndexedMap::new();
        let mut global_comms = vec![Point::zero(SCHEME); n as usize];
        let threshold = 2 * n / 3;

        let mut peer_ids = generate_peer_ids(n);
        peer_ids.sort();

        let mut peer_secrets = vec![Scalar::zero(SCHEME); n as usize];
        for i in 0..n {
            let (de_shares, comms) = Vss::share(&SCHEME, threshold, n);
            for (index, de_share) in de_shares.iter() {
                peer_secrets[(index - 1) as usize] =
                    peer_secrets[(index - 1) as usize].add(de_share).unwrap();
            }
            for comm in comms {
                global_comms[i as usize] = global_comms[i as usize].add(&comm).unwrap();
            }
        }

        for (i, peer_id) in peer_ids.iter().enumerate() {
            peers.insert(*peer_id, peer_secrets[i].clone());
        }

        (peers, global_comms, threshold)
    }

    fn generate_peer_ids(n: u16) -> Vec<libp2p::PeerId> {
        (0..n).map(|_| libp2p::PeerId::random()).collect()
    }

    #[test]
    fn initialize() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);

        let session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        assert!(session.shares.is_empty());
        assert_eq!(session.pending_peers.len(), NUM_PEERS as usize);
        assert!(session.invalid_peers.is_empty());
        assert_eq!(session.global_comms.len(), NUM_PEERS as usize);
        assert!(!session.completed);
    }

    #[test]
    fn add_valid_share_increases_share_count() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let peer_id = *peers.keys().next().unwrap();
        let peer_index = peers.get_index(&peer_id).unwrap();
        let share = peers.get(&peer_id).unwrap().clone();

        session.add_share(peer_id, peer_index, share);

        assert_eq!(session.shares.len(), 1);
        assert_eq!(session.pending_peers.len(), NUM_PEERS as usize - 1);
        assert!(session.invalid_peers.is_empty());
    }

    #[test]
    fn add_invalid_share_marks_peer_as_invalid() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let peer_id = *peers.keys().next().unwrap();
        let peer_index = peers.get_index(&peer_id).unwrap();
        let invalid_share = Scalar::zero(SCHEME);

        session.add_share(peer_id, peer_index, invalid_share);

        assert_eq!(session.shares.len(), 0);
        assert_eq!(session.pending_peers.len(), NUM_PEERS as usize - 1);
        assert_eq!(session.invalid_peers.len(), 1);
    }

    #[test]
    fn ignored_shares_after_completion() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let (tx, _) = tokio::sync::oneshot::channel();
        session.force_completion(tx);

        let peer_id = *peers.keys().next().unwrap();
        let peer_index = peers.get_index(&peer_id).unwrap();
        let share = peers.get(&peer_id).unwrap().clone();

        session.add_share(peer_id, peer_index, share);

        assert!(session.shares.is_empty());
        assert!(session.completed);
    }

    #[tokio::test]
    async fn triggers_callback_at_threshold() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let (tx, rx) = tokio::sync::oneshot::channel();
        session.set_callback(tx);

        for (peer_id, share) in peers.iter() {
            let peer_index = peers.get_index(peer_id).unwrap();
            session.add_share(*peer_id, peer_index, share.clone());
        }

        let result = rx.await.unwrap();
        match result {
            CollectionResult::Success(shares) => {
                assert_eq!(shares.len(), threshold as usize);
                assert_eq!(session.shares.len(), threshold as usize);
                assert!(session.completed);
            }
            _ => panic!("Expected success result"),
        }
    }

    #[test]
    fn not_completes_if_threshold_not_reached() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let (tx, _) = tokio::sync::oneshot::channel();
        session.set_callback(tx);

        for (peer_id, share) in peers.iter().take((threshold - 1) as usize) {
            let peer_index = peers.get_index(peer_id).unwrap();
            session.add_share(*peer_id, peer_index, share.clone());
        }

        assert!(!session.completed);
    }

    #[tokio::test]
    async fn set_callback_completes_if_already_at_threshold() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        for (peer_id, share) in peers.iter().take(threshold as usize) {
            let peer_index = peers.get_index(peer_id).unwrap();
            session.add_share(*peer_id, peer_index, share.clone());
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        session.set_callback(tx);

        let result = rx.await.unwrap();
        match result {
            CollectionResult::Success(shares) => {
                assert_eq!(shares.len(), threshold as usize);
                assert_eq!(session.shares.len(), threshold as usize);
                assert!(session.completed);
            }
            _ => panic!("Expected success result"),
        }
    }

    #[tokio::test]
    async fn force_completion_sends_failure_if_threshold_not_reached() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        for (peer_id, share) in peers.iter().take((threshold - 1) as usize) {
            let peer_index = peers.get_index(peer_id).unwrap();
            session.add_share(*peer_id, peer_index, share.clone());
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        session.force_completion(tx);

        let result = rx.await.unwrap();
        match result {
            CollectionResult::Failure(invalid_peers) => {
                assert_eq!(
                    invalid_peers.len(),
                    NUM_PEERS as usize - (threshold - 1) as usize
                );
                assert!(session.completed);
            }
            _ => panic!("Expected failure result"),
        }
    }

    #[test]
    fn ignores_already_existing_peer() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let peer_id = *peers.keys().next().unwrap();
        let peer_index = peers.get_index(&peer_id).unwrap();
        let share = peers.get(&peer_id).unwrap().clone();

        session.add_share(peer_id, peer_index, share.clone());
        session.add_share(peer_id, peer_index, share.clone());

        assert_eq!(session.shares.len(), 1);
    }

    #[test]
    fn ignores_invalid_peer() {
        let (peers, global_comms, threshold) = setup(NUM_PEERS);
        let mut session = Session::new(peers.keys().cloned(), global_comms.clone(), threshold);

        let peer_id = *peers.keys().next().unwrap();
        let peer_index = peers.get_index(&peer_id).unwrap();
        let invalid_share = Scalar::zero(SCHEME);

        session.add_share(peer_id, peer_index, invalid_share.clone());
        session.add_share(peer_id, peer_index, invalid_share.clone());

        assert!(session.shares.is_empty());
        assert!(session.invalid_peers.contains(&peer_id));
        assert_eq!(session.invalid_peers.len(), 1);
    }
}
