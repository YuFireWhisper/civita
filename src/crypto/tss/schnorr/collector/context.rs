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

#[cfg(test)]
mod tests {
    use crate::crypto::{
        index_map::IndexedMap,
        primitives::{
            algebra::{Point, Scalar, Scheme},
            vss::Vss,
        },
        tss::schnorr::collector::{context::Context, SessionId},
    };

    const SCHEME: Scheme = Scheme::Secp256k1;
    const NUM_PEERS: u16 = 3;

    fn setup(
        n: u16,
    ) -> (
        IndexedMap<libp2p::PeerId, Vec<Point>>,
        IndexedMap<libp2p::PeerId, Scalar>,
        u16,
    ) {
        let threshold = 2 * n / 3 + 1;
        let mut peer_ids = generate_peer_ids(n);
        peer_ids.sort();

        let mut peer_pks = IndexedMap::new();
        let mut peer_secrets = vec![Scalar::zero(SCHEME); n as usize];

        for peer_id in &peer_ids {
            let (de_shares, comms) = Vss::share(&SCHEME, threshold, n);

            for (index, de_share) in de_shares.iter() {
                let idx = (index - 1) as usize;
                peer_secrets[idx] = peer_secrets[idx].add(de_share).unwrap();
            }

            peer_pks.insert(*peer_id, comms);
        }

        let peer_secrets_map = peer_ids
            .iter()
            .enumerate()
            .map(|(i, peer_id)| (*peer_id, peer_secrets[i].clone()))
            .collect::<IndexedMap<_, _>>();

        (peer_pks, peer_secrets_map, threshold)
    }

    fn generate_peer_ids(n: u16) -> Vec<libp2p::PeerId> {
        let mut peer_ids = Vec::new();
        for _ in 0..n {
            peer_ids.push(libp2p::PeerId::random());
        }
        peer_ids
    }

    fn create_session_id(n: u16) -> SessionId {
        SessionId::NonceShare(vec![0; n as usize])
    }

    #[test]
    fn initialize_with_correct_parameters() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let context = Context::new(threshold, peer_pks.clone());

        assert_eq!(context.threshold, threshold);
        assert_eq!(context.global_comms.len(), threshold as usize);
        assert_eq!(context.peers_index.len(), NUM_PEERS);
    }

    #[test]
    fn calculate_global_comms_should_sum_all_points() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let mut expected_global_comms = vec![Point::zero(SCHEME); threshold as usize];
        for (_, pks) in peer_pks.iter() {
            for (i, pk) in pks.iter().enumerate() {
                expected_global_comms[i] = expected_global_comms[i].add(pk).unwrap();
            }
        }

        let context = Context::new(threshold, peer_pks.clone());

        assert_eq!(context.global_comms, expected_global_comms);
    }

    #[test]
    fn add_share_should_ignore_unknown_peers() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let context = Context::new(threshold, peer_pks.clone());

        let peer_id = libp2p::PeerId::random();
        let share = Scalar::random(&SCHEME);

        context.add_share(create_session_id(1), peer_id, share);

        assert_eq!(context.session.len(), 0);
    }

    #[test]
    fn add_valid_share_should_add_to_session() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let context = Context::new(threshold, peer_pks.clone());

        let peer_id = peer_pks.keys().next().unwrap();
        let share = Scalar::random(&SCHEME);

        context.add_share(create_session_id(1), *peer_id, share);

        assert_eq!(context.session.len(), 1);
    }

    #[test]
    fn register_callback_should_create_session_if_not_exists() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let context = Context::new(threshold, peer_pks.clone());

        let session_id = create_session_id(1);
        let (tx, _rx) = tokio::sync::oneshot::channel();

        context.register_callback(session_id, tx);

        assert_eq!(context.session.len(), 1);
    }

    #[test]
    fn cleanup_completed_sessions_should_remove_only_completed_sessions() {
        let (peer_pks, _, threshold) = setup(NUM_PEERS);
        let context = Context::new(threshold, peer_pks.clone());

        let completed_session_id = create_session_id(1);
        let (tx, _) = tokio::sync::oneshot::channel();
        context.force_completion(completed_session_id.clone(), tx);

        let active_session_id = create_session_id(2);
        let (tx, _) = tokio::sync::oneshot::channel();
        context.register_callback(active_session_id.clone(), tx);

        context.cleanup_completed_sessions();

        assert!(!context.session.contains_key(&completed_session_id));
        assert!(context.session.contains_key(&active_session_id));
        assert_eq!(context.session.len(), 1);
    }
}
