use std::collections::{HashMap, HashSet};

use crate::crypto::{
    dkg::joint_feldman::peer_info::PeerRegistry,
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::element::{self, Point, Scalar},
        vss::{
            encrypted_share::{self, EncryptedShare, EncryptedShares},
            Vss,
        },
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Keypair operation failed: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Share not found for peer with index {0}")]
    ShareNotFound(u16),

    #[error("Peer with ID {0} not found")]
    PeerNotFound(libp2p::PeerId),

    #[error("Event with ID {0} not found")]
    EventNotFound(String),

    #[error("Event with ID {0} already processed")]
    EventAlreadyProcessed(String),

    #[error("Report not found for reporter {0} against reported {1}")]
    ReportNotFound(String, String),

    #[error("Report already exists for reporter {0} against reported {1}")]
    ReportAlreadyExists(String, String),

    #[error("Element error: {0}")]
    Element(#[from] element::Error),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),
}

#[derive(Debug)]
pub struct Bundle {
    pub encrypted_shares: EncryptedShares,
    pub commitments: Vec<Point>,
}

pub enum EventResult {
    Success {
        bundle: HashMap<libp2p::PeerId, (Scalar, Vec<Point>)>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerificationResult {
    ReportedPeerMalicious,
    ReporterPeerMalicious,
    Pending,
}

#[derive(Debug)]
struct Report {
    reporter: libp2p::PeerId,
    reported: libp2p::PeerId,
    raw_share: Option<Scalar>,
    result: VerificationResult,
}

#[derive(Debug)]
pub struct Event {
    pairs: HashMap<u16, Bundle>,
    own_peer: libp2p::PeerId,
    own_share: Option<Scalar>,
    // (reporter, reported)
    reports: HashMap<(libp2p::PeerId, libp2p::PeerId), Report>,
    // Reports against self that need responses
    pending_self_reports: HashSet<libp2p::PeerId>,
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

impl Bundle {
    pub fn new(encrypted_shares: EncryptedShares, commitments: Vec<Point>) -> Self {
        Self {
            encrypted_shares,
            commitments,
        }
    }
}

impl Event {
    pub fn new(own_peer: libp2p::PeerId) -> Self {
        Self {
            pairs: HashMap::new(),
            own_peer,
            own_share: None,
            reports: HashMap::new(),
            pending_self_reports: HashSet::new(),
        }
    }

    pub fn add_pair(&mut self, source_index: u16, bundle: Bundle) {
        self.pairs.insert(source_index, bundle);
    }

    pub fn set_own_share(&mut self, own_share: Scalar) {
        self.own_share = Some(own_share);
    }

    pub fn add_report(&mut self, reporter: libp2p::PeerId, reported: libp2p::PeerId) -> Result<()> {
        let key = (reporter, reported);
        if self.reports.contains_key(&key) {
            return Err(Error::ReportAlreadyExists(
                reporter.to_string(),
                reported.to_string(),
            ));
        }

        self.reports.insert(
            key,
            Report {
                reporter,
                reported,
                raw_share: None,
                result: VerificationResult::Pending,
            },
        );

        if reported == self.own_peer {
            self.pending_self_reports.insert(reporter);
        }

        Ok(())
    }

    pub fn pending_reports_against_self(&self) -> Vec<libp2p::PeerId> {
        self.pending_self_reports.iter().copied().collect()
    }

    pub fn mark_self_report_as_responded(&mut self, reporter: &libp2p::PeerId) {
        self.pending_self_reports.remove(reporter);
    }

    pub fn respond_to_report<V: Vss>(
        &mut self,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Scalar,
        reporter_index: u16,
        reported_index: u16,
        reporter_public_key: &PublicKey,
    ) -> Result<()> {
        let key = (reporter, reported);
        let report = self.reports.get_mut(&key).ok_or(Error::ReportNotFound(
            reporter.to_string(),
            reported.to_string(),
        ))?;

        report.raw_share = Some(raw_share.clone());

        let accused_share = self
            .pairs
            .get(&reported_index)
            .ok_or(Error::ShareNotFound(reported_index))?;

        Self::verify_and_update_report::<V>(
            report,
            &raw_share,
            accused_share,
            reporter_index,
            reporter_public_key,
        )?;

        Ok(())
    }

    fn verify_and_update_report<V: Vss>(
        report: &mut Report,
        reported_raw_share: &Scalar,
        reported_bundle: &Bundle,
        reporter_index: u16,
        reporter_public_key: &PublicKey,
    ) -> Result<()> {
        let encrypted_share = match reported_bundle.encrypted_shares.get(&reporter_index) {
            Some(share) => share,
            None => {
                report.result = VerificationResult::ReportedPeerMalicious;
                return Ok(());
            }
        };

        if !is_share_matching(reported_raw_share, encrypted_share, reporter_public_key)? {
            report.result = VerificationResult::ReportedPeerMalicious;
            return Ok(());
        }

        report.result = if V::verify(
            &reporter_index,
            reported_raw_share,
            &reported_bundle.commitments,
        ) {
            VerificationResult::ReporterPeerMalicious
        } else {
            VerificationResult::ReportedPeerMalicious
        };

        Ok(())
    }

    pub fn encrypted_shares(&self, index: &u16) -> Result<&EncryptedShares> {
        self.pairs
            .get(index)
            .ok_or(Error::ShareNotFound(*index))
            .map(|pair| &pair.encrypted_shares)
    }

    pub fn own_share_ref(&self) -> Option<&Scalar> {
        self.own_share.as_ref()
    }

    pub fn get_malicious_peers(&self) -> HashSet<libp2p::PeerId> {
        let mut malicious = HashSet::new();

        for report in self.reports.values() {
            match report.result {
                VerificationResult::ReportedPeerMalicious => {
                    malicious.insert(report.reported);
                }
                VerificationResult::ReporterPeerMalicious => {
                    malicious.insert(report.reporter);
                }
                VerificationResult::Pending => {
                    malicious.insert(report.reported);
                }
            }
        }

        malicious
    }

    pub fn decrypted_share(&self, index: &u16, secret_key: &SecretKey) -> Result<Scalar> {
        let encrypted_share = self
            .encrypted_shares(index)?
            .get(index)
            .ok_or(Error::ShareNotFound(*index))?;
        encrypted_share.to_scalar(secret_key).map_err(Error::from)
    }

    pub fn commitments(&self, index: &u16) -> Result<&Vec<Point>> {
        self.pairs
            .get(index)
            .ok_or(Error::ShareNotFound(*index))
            .map(|pair| &pair.commitments)
    }
}

fn is_share_matching(
    raw_share: &Scalar,
    encrypted_share: &EncryptedShare,
    public_key: &PublicKey,
) -> Result<bool> {
    let raw_share_bytes = raw_share.to_vec()?;
    let expected_encrypted_share = public_key.encrypt(&raw_share_bytes)?;
    Ok(encrypted_share.as_slice() == expected_encrypted_share)
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

    pub fn add_report_response<V: Vss>(
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
        event.respond_to_report::<V>(
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
                .reports
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
