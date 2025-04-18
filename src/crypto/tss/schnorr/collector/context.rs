use dashmap::{mapref::one::RefMut, DashMap};

use tokio::sync::oneshot::Sender as TokioOneShotSender;

use crate::crypto::{
    index_map::IndexedMap,
    primitives::algebra::{self, Point, Scalar},
    tss::schnorr::collector::{session::Session, CollectionResult, SessionId},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Algebra(#[from] algebra::Error),
}

#[derive(Debug)]
#[derive(Default)]
pub struct Context {
    session: DashMap<SessionId, Session>,
    threshold: u16,
    global_comms: Vec<Point>,
    peers_index: IndexedMap<libp2p::PeerId, ()>,
}

impl Context {
    pub fn new(threshold: u16, partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>) -> Self {
        let (global_comms, peers_index) =
            Self::calculate_global_comms_and_convert_to_set(partial_pks)
                .expect("Failed to calculate global commitments");

        Self {
            session: DashMap::new(),
            threshold,
            global_comms,
            peers_index,
        }
    }

    fn calculate_global_comms_and_convert_to_set(
        partial_pks: IndexedMap<libp2p::PeerId, Vec<Point>>,
    ) -> Result<(Vec<Point>, IndexedMap<libp2p::PeerId, ()>)> {
        let mut set = IndexedMap::new();

        let len = partial_pks
            .values()
            .next()
            .expect("Partial PKs should not empty")
            .len();
        let scheme = partial_pks
            .values()
            .next()
            .expect("Partial PKs should not empty")
            .first()
            .expect("Partial PKs should not empty")
            .scheme();
        let mut global_comms = vec![Point::zero(scheme); len];

        for (peer_id, pks) in partial_pks.into_iter() {
            for (i, pk) in pks.iter().enumerate() {
                global_comms[i] = global_comms[i].add(pk)?;
            }

            set.insert(peer_id, ());
        }

        Ok((global_comms, set))
    }

    pub fn add_share(&self, session_id: SessionId, peer_id: libp2p::PeerId, share: Scalar) {
        if !self.peers_index.contains_key(&peer_id) {
            return;
        }

        let index = self.get_index_or_unwrap(&peer_id);
        let mut session = self.get_or_create_session(session_id);
        session.add_share(peer_id, index, share);
    }

    fn get_or_create_session(&self, id: SessionId) -> RefMut<'_, SessionId, Session> {
        self.session.entry(id).or_insert_with(|| {
            let peers = self.peers_index.keys().cloned();
            Session::new(peers, self.global_comms.clone(), self.threshold)
        })
    }

    fn get_index_or_unwrap(&self, peer_id: &libp2p::PeerId) -> u16 {
        self.peers_index
            .get_index(peer_id)
            .expect("Peer ID in the peers index")
    }

    pub fn register_callback(&self, id: SessionId, callback: TokioOneShotSender<CollectionResult>) {
        let mut session = self.get_or_create_session(id);
        session.set_callback(callback);
    }

    pub fn force_completion(&self, id: SessionId, callback: TokioOneShotSender<CollectionResult>) {
        let mut session = self.get_or_create_session(id);
        session.force_completion(callback);
    }

    pub fn cleanup_completed_sessions(&self) {
        let completed_keys: Vec<SessionId> = self
            .session
            .iter()
            .filter_map(|entry| {
                if entry.is_completed() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        for key in completed_keys {
            self.session.remove(&key);
        }
    }
}
