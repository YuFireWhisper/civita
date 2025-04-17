use std::sync::Arc;

use dashmap::{mapref::one::RefMut, DashMap, DashSet};

use crate::crypto::{
    dkg::joint_feldman::collector::event::{self, ActionNeeded, Event},
    keypair::SecretKey,
    peer_registry::PeerRegistry,
    primitives::{
        algebra::{self, Point},
        vss::{
            encrypted_share::{self, EncryptedShares},
            DecryptedShares,
        },
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Share not found for index: {0}")]
    ShareNotFound(u16),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

    #[error("Event already processed: {0}")]
    EventAlreadyProcessed(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(libp2p::PeerId),

    #[error("Event not found: {0}")]
    EventNotFound(String),

    #[error("Event error: {0}")]
    Event(#[from] event::Error),
}

#[derive(Debug)]
pub struct Context {
    peers: Arc<PeerRegistry>,
    secret_key: Arc<SecretKey>,
    own_peer: libp2p::PeerId,
    events: DashMap<Vec<u8>, Event>,
    processed_events: DashSet<Vec<u8>>,
}

impl Context {
    pub fn new(peers: PeerRegistry, secret_key: Arc<SecretKey>, own_peer: libp2p::PeerId) -> Self {
        let peers = Arc::new(peers);

        Self {
            peers,
            secret_key,
            own_peer,
            events: DashMap::new(),
            processed_events: DashSet::new(),
        }
    }

    pub fn set_own_component(
        &self,
        id: Vec<u8>,
        de_shares: DecryptedShares,
        comms: Vec<Point>,
    ) -> Result<ActionNeeded> {
        self.ensure_event_not_processed(&id)?;

        let mut event = self.get_or_create_event(&id);
        Ok(event.set_own_components(de_shares, comms))
    }

    pub fn handle_component(
        &self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        en_shares: EncryptedShares,
        comms: Vec<Point>,
    ) -> Result<ActionNeeded> {
        self.ensure_event_not_processed(&id)?;

        let mut event = self.get_or_create_event(&id);
        event
            .add_en_shares_and_comms(source, en_shares, comms)
            .map_err(Error::from)
    }

    fn ensure_event_not_processed(&self, id: &[u8]) -> Result<()> {
        if self.processed_events.contains(id) {
            return Err(Error::EventAlreadyProcessed(
                String::from_utf8_lossy(id).to_string(),
            ));
        }
        Ok(())
    }

    fn get_or_create_event(&self, id: &[u8]) -> RefMut<Vec<u8>, Event> {
        self.events.entry(id.to_vec()).or_insert_with(move || {
            Event::new(self.peers.clone(), self.secret_key.clone(), self.own_peer)
        })
    }

    pub fn handle_report(
        &self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        de_share: DecryptedShares,
    ) -> Result<ActionNeeded> {
        self.ensure_event_not_processed(&id)?;

        let mut event = self.get_or_create_event(&id);
        event.add_reporter(source, de_share).map_err(Error::from)
    }

    pub fn handle_report_response(
        &self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        de_share: DecryptedShares,
    ) -> Result<ActionNeeded> {
        self.ensure_event_not_processed(&id)?;

        let mut event = self.get_or_create_event(&id);
        event
            .add_decrypted_shares(source, de_share)
            .map_err(Error::from)
    }

    fn ensure_event_exists(&self, id: &[u8]) -> Result<()> {
        if !self.events.contains_key(id) {
            return Err(Error::EventNotFound(
                String::from_utf8_lossy(id).to_string(),
            ));
        }
        Ok(())
    }

    pub fn output(&self, id: Vec<u8>) -> Result<event::Output> {
        self.ensure_event_not_processed(&id)?;
        self.ensure_event_exists(&id)?;

        self.processed_events.insert(id.clone());
        let event = self.remove_event(&id)?;

        Ok(event.output())
    }

    fn remove_event(&self, id: &[u8]) -> Result<Event> {
        self.events
            .remove(id)
            .map(|entry| entry.1)
            .ok_or_else(|| Error::EventNotFound(String::from_utf8_lossy(id).to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::crypto::{
        dkg::joint_feldman::collector::context::{Context, Error},
        keypair::{self},
        peer_registry::PeerRegistry,
        primitives::{
            algebra::Scheme,
            vss::{EncryptedShares, Vss},
        },
    };

    const NUM_PEERS: u16 = 3;
    const THRESHOLD: u16 = 2;
    const SCHEME: Scheme = Scheme::Secp256k1;
    const ID: [u8; 32] = [0; 32];

    fn setup(num: u16) -> (Context, PeerRegistry) {
        let mut peers = HashMap::new();
        let own_peer = libp2p::PeerId::random();
        let (own_sk, own_pk) = keypair::generate_secp256k1();

        peers.insert(own_peer, own_pk);
        for _ in 1..num {
            let peer_id = libp2p::PeerId::random();
            let (_, pk) = keypair::generate_secp256k1();
            peers.insert(peer_id, pk);
        }

        let peers = PeerRegistry::new(peers);
        let secret_key = Arc::new(own_sk);

        (Context::new(peers.clone(), secret_key, own_peer), peers)
    }

    #[test]
    fn initialization_correctness() {
        let (context, _) = setup(NUM_PEERS);
        assert_eq!(context.peers.len(), NUM_PEERS);
    }

    #[test]
    fn set_own_component_correctness() {
        let (context, _) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let (de_shares, comms) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

        let result = context.set_own_component(id.clone(), de_shares, comms);

        assert!(result.is_ok(), "Failed to set own component");
        assert_eq!(context.events.len(), 1);
        assert!(context.events.contains_key(&id));
    }

    #[test]
    fn handle_component_correctness() {
        const TARGET_INDEX: u16 = 1;

        let (context, peers) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let peer_id = peers.get_peer_id_by_index(TARGET_INDEX).unwrap();
        let (de_shares, comms) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);
        let en_shares =
            EncryptedShares::from_decrypted(&de_shares, peers.iter_index_keys()).unwrap();

        let result = context.handle_component(id.clone(), *peer_id, en_shares, comms);

        assert!(result.is_ok());
        assert_eq!(context.events.len(), 1);
        assert!(context.events.contains_key(&id));
    }

    #[test]
    fn handle_report_correctness() {
        const TARGET_INDEX: u16 = 1;

        let (context, peers) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let peer_id = peers.get_peer_id_by_index(TARGET_INDEX).unwrap();
        let (de_shares, _) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

        let result = context.handle_report(id.clone(), *peer_id, de_shares);

        assert!(result.is_ok());
        assert_eq!(context.events.len(), 1);
        assert!(context.events.contains_key(&id));
    }

    #[test]
    fn handle_report_response_correctness() {
        const TARGET_INDEX: u16 = 1;

        let (context, peers) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let peer_id = peers.get_peer_id_by_index(TARGET_INDEX).unwrap();
        let (de_shares, _) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

        let result = context.handle_report_response(id.clone(), *peer_id, de_shares);

        assert!(result.is_ok());
        assert_eq!(context.events.len(), 1);
        assert!(context.events.contains_key(&id));
    }

    #[test]
    fn output_correctness() {
        let (context, _) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let (de_shares, comms) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

        context
            .set_own_component(id.clone(), de_shares, comms)
            .unwrap();
        let result = context.output(id.clone());

        assert!(result.is_ok());
        assert_eq!(context.events.len(), 0);
        assert!(!context.events.contains_key(&id));
    }

    #[test]
    fn return_error_event_already_processed() {
        let (context, _) = setup(NUM_PEERS);
        let id = ID.to_vec();
        let (de_shares, comms) = Vss::share(&SCHEME, THRESHOLD, NUM_PEERS);

        context
            .set_own_component(id.clone(), de_shares.clone(), comms.clone())
            .unwrap();
        context.output(id.clone()).unwrap();

        let result = context.set_own_component(id.clone(), de_shares, comms);

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::EventAlreadyProcessed(_))));
    }

    #[test]
    fn return_error_event_not_found() {
        let (context, _) = setup(NUM_PEERS);
        let id = ID.to_vec();

        let result = context.output(id.clone());

        assert!(result.is_err());
        assert!(matches!(result, Err(Error::EventNotFound(_))));
    }
}
