use std::collections::{HashMap, HashSet};

use crate::crypto::{
    dkg::joint_feldman::{
        collector::event::{self, Bundle, Event, EventResult},
        peer_registry::PeerRegistry,
    },
    keypair::{PublicKey, SecretKey},
    primitives::{
        algebra::{self, Point, Scalar},
        vss::encrypted_share::{self, EncryptedShares},
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
    peers: PeerRegistry,
    invalid_peers: HashSet<libp2p::PeerId>,
    secret_key: SecretKey,
    own_peer: libp2p::PeerId,
    own_index: u16,
    events: HashMap<Vec<u8>, Event>,
    processed_events: HashSet<Vec<u8>>,
    events_awaiting_own_share: HashSet<Vec<u8>>,
}

impl Context {
    pub fn new(peers: PeerRegistry, secret_key: SecretKey, own_peer: libp2p::PeerId) -> Self {
        let own_index = peers.get_index(&own_peer).expect("Own peer not found");

        Self {
            peers,
            invalid_peers: HashSet::new(),
            secret_key,
            own_peer,
            own_index,
            events: HashMap::new(),
            processed_events: HashSet::new(),
            events_awaiting_own_share: HashSet::new(),
        }
    }

    pub fn add_event(
        &mut self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        encrypted_shares: EncryptedShares,
        commitments: Vec<Point>,
    ) -> Result<()> {
        if !self.is_valid_source(&source) {
            return Ok(());
        }

        self.ensure_event_not_processed(&id)?;

        let encrypted_share = encrypted_shares
            .get(&self.own_index)
            .ok_or(Error::ShareNotFound(self.own_index))?;
        let own_share = encrypted_share.to_scalar(&self.secret_key)?;

        if own_share.verify(self.own_index, &commitments)? {
            let index = self.peer_index(source)?;
            let event = self.get_or_create_event(&id);
            let bundle = Bundle::new(encrypted_shares, commitments);
            event.add_pair(index, bundle);
        } else {
            self.invalid_peers.insert(source);
        }

        Ok(())
    }

    fn is_valid_source(&self, source: &libp2p::PeerId) -> bool {
        !self.invalid_peers.contains(source) && self.peers.contains(source)
    }

    fn ensure_event_not_processed(&self, id: &[u8]) -> Result<()> {
        if self.processed_events.contains(id) {
            return Err(Error::EventAlreadyProcessed(
                String::from_utf8_lossy(id).to_string(),
            ));
        }
        Ok(())
    }

    fn get_or_create_event(&mut self, id: &[u8]) -> &mut Event {
        self.events
            .entry(id.to_vec())
            .or_insert_with(|| Event::new(self.own_peer))
    }

    pub fn set_own_share(&mut self, id: Vec<u8>, own_share: Scalar) -> Result<Option<Scalar>> {
        self.ensure_event_not_processed(&id)?;

        if self.events_awaiting_own_share.remove(&id) {
            return Ok(Some(own_share));
        }

        let event = self.get_or_create_event(&id);
        event.set_own_share(own_share);

        Ok(None)
    }

    fn peer_index(&self, peer_id: libp2p::PeerId) -> Result<u16> {
        self.peers
            .get_index(&peer_id)
            .ok_or(Error::PeerNotFound(peer_id))
    }

    pub fn add_report_peer(
        &mut self,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
    ) -> Result<()> {
        if !self.are_peers_valid(&reporter, &reported) {
            return Ok(());
        }

        self.ensure_event_not_processed(&id)?;
        self.validate_peers_exist(&reporter, &reported)?;

        let event = self.get_or_create_event(&id);
        event.add_report(reporter, reported)?;

        Ok(())
    }

    fn are_peers_valid(&self, reporter: &libp2p::PeerId, reported: &libp2p::PeerId) -> bool {
        !self.invalid_peers.contains(reporter) && !self.invalid_peers.contains(reported)
    }

    fn validate_peers_exist(
        &self,
        reporter: &libp2p::PeerId,
        reported: &libp2p::PeerId,
    ) -> Result<()> {
        self.peer_index(*reporter)?;
        self.peer_index(*reported)?;
        Ok(())
    }

    pub fn get_pending_reports_against_self(&self, id: &[u8]) -> Vec<libp2p::PeerId> {
        self.events
            .get(id)
            .map_or_else(Vec::new, |event| event.pending_reports_against_self())
    }

    pub fn mark_self_report_as_responded(
        &mut self,
        id: &[u8],
        reporter: &libp2p::PeerId,
    ) -> Result<()> {
        let event = self.get_event_mut(id)?;
        event.mark_self_report_as_responded(reporter);
        Ok(())
    }

    fn get_event_mut(&mut self, id: &[u8]) -> Result<&mut Event> {
        self.events
            .get_mut(id)
            .ok_or_else(|| Error::EventNotFound(String::from_utf8_lossy(id).to_string()))
    }

    pub fn add_report_response(
        &mut self,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Scalar,
    ) -> Result<()> {
        if !self.are_peers_valid(&reporter, &reported) {
            return Ok(());
        }

        self.ensure_event_not_processed(&id)?;
        self.ensure_event_exists(&id)?;

        let reporter_index = self.peer_index(reporter)?;
        let reported_index = self.peer_index(reported)?;
        let reporter_public_key = self.peer_public_key(&reporter)?;

        let event = self.get_event_mut(&id)?;
        event.respond_to_report(
            reporter,
            reported,
            raw_share,
            reporter_index,
            reported_index,
            &reporter_public_key,
        )?;

        Ok(())
    }

    fn ensure_event_exists(&self, id: &[u8]) -> Result<()> {
        if !self.events.contains_key(id) {
            return Err(Error::EventNotFound(
                String::from_utf8_lossy(id).to_string(),
            ));
        }
        Ok(())
    }

    fn peer_public_key(&self, peer: &libp2p::PeerId) -> Result<PublicKey> {
        self.peers
            .get_public_key_by_peer_id(peer)
            .cloned()
            .ok_or(Error::PeerNotFound(*peer))
    }

    pub fn output(&mut self, id: Vec<u8>) -> Result<EventResult> {
        self.ensure_event_not_processed(&id)?;

        let event = self
            .events
            .remove(&id)
            .ok_or_else(|| Error::EventNotFound(String::from_utf8_lossy(&id).to_string()))?;

        let mut malicious_peers = event.get_malicious_peers();
        malicious_peers.extend(&self.invalid_peers);
        self.invalid_peers.extend(&malicious_peers);

        self.processed_events.insert(id);

        if !malicious_peers.is_empty() {
            return Ok(EventResult::Failure {
                invalid_peers: malicious_peers,
            });
        }

        let shares_map = self.collect_valid_shares(&event);

        Ok(EventResult::Success { bundle: shares_map })
    }

    fn collect_valid_shares(&self, event: &Event) -> HashMap<libp2p::PeerId, (Scalar, Vec<Point>)> {
        let mut shares_map = HashMap::new();
        for (peer, index) in &self.peers {
            if let (Ok(share), Ok(commitments)) = (
                event.decrypted_share(&index, &self.secret_key),
                event.commitments(&index),
            ) {
                shares_map.insert(peer, (share, commitments.clone()));
            }
        }
        shares_map
    }

    pub fn own_share_clone(&mut self, id: &[u8]) -> Result<Option<Scalar>> {
        self.ensure_event_not_processed(id)?;

        let event = match self.events.get(id) {
            Some(event) => event,
            None => {
                self.events_awaiting_own_share.insert(id.to_vec());
                return Ok(None);
            }
        };

        Ok(event.own_share_ref().cloned())
    }

    pub fn active_event_ids(&self) -> Vec<Vec<u8>> {
        self.events.keys().cloned().collect()
    }

    pub fn get_reporters_of(&self, id: &[u8], reported: libp2p::PeerId) -> Vec<libp2p::PeerId> {
        self.events.get(id).map_or_else(Vec::new, |event| {
            event
                .reports()
                .keys()
                .filter_map(|(reporter, reported_peer)| {
                    if *reported_peer == reported {
                        Some(*reporter)
                    } else {
                        None
                    }
                })
                .collect()
        })
    }
}
