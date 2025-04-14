use std::collections::{HashMap, HashSet};

use crate::crypto::{
    dkg::joint_feldman::peer_info::PeerRegistry,
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::element::{self, Point, Scalar},
        vss::{Shares, SharesError, Vss},
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Keypair operation failed: {0}")]
    Keypair(#[from] keypair::Error),

    #[error("Share not found for peer with index {0}")]
    ShareNotFound(u16),

    #[error("Peer with ID {0} not found")]
    PeerNotFound(libp2p::PeerId),

    #[error("Event with ID {0} not found")]
    EventNotFound(String),

    #[error("Event with ID {0} already output")]
    EventAlreadyOutput(String),

    #[error("Report not found for reporter {0} against reported {1}")]
    ReportNotFound(String, String),

    #[error("Report already exists for reporter {0} against reported {1}")]
    ReportAlreadyExists(String, String),

    #[error("Element error: {0}")]
    Element(#[from] element::Error),

    #[error("Share error: {0}")]
    Share(#[from] SharesError),
}

pub enum EventResult {
    Success {
        own_index: u16,
        shares: HashMap<libp2p::PeerId, Shares>,
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
    raw_share: Option<Vec<u8>>,
    result: VerificationResult,
}

#[derive(Debug)]
pub struct Event {
    pairs: HashMap<u16, Shares>,
    onw_peer: libp2p::PeerId,
    own_share: Option<Vec<u8>>,
    // (reporter, reported)
    reports: HashMap<(libp2p::PeerId, libp2p::PeerId), Report>,
    // Reports against self that need responses
    pending_self_reports: HashSet<libp2p::PeerId>, // Reporters that need a response
}

#[derive(Debug)]
pub struct Context {
    peers: PeerRegistry,
    invalid_peers: HashSet<libp2p::PeerId>,
    secret_key: SecretKey,
    own_peer: libp2p::PeerId,
    own_index: u16,
    events: HashMap<Vec<u8>, Event>,
    is_output: HashSet<Vec<u8>>,
    waiting_own_share: HashSet<Vec<u8>>,
}

impl Event {
    pub fn new(own_peer: libp2p::PeerId) -> Self {
        Self {
            pairs: HashMap::new(),
            onw_peer: own_peer,
            own_share: None,
            reports: HashMap::new(),
            pending_self_reports: HashSet::new(),
        }
    }
    pub fn add_pair(&mut self, source_index: u16, shares: Shares) {
        self.pairs.insert(source_index, shares);
    }

    pub fn set_own_share(&mut self, own_share: Vec<u8>) {
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

        if reported == self.onw_peer {
            self.pending_self_reports.insert(reporter);
        }

        Ok(())
    }

    pub fn pending_reports_against_self(&self) -> Vec<libp2p::PeerId> {
        self.pending_self_reports.iter().cloned().collect()
    }

    pub fn mark_self_report_as_responded(&mut self, reporter: &libp2p::PeerId) {
        self.pending_self_reports.remove(reporter);
    }

    pub fn respond_to_report<V: Vss>(
        &mut self,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Vec<u8>,
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

        let encrypted_share = match accused_share.shares.get(&reporter_index) {
            Some(share) => share,
            None => {
                report.result = VerificationResult::ReportedPeerMalicious;
                return Ok(());
            }
        };

        if !is_share_matching(&raw_share, encrypted_share, reporter_public_key)? {
            report.result = VerificationResult::ReportedPeerMalicious;
            return Ok(());
        }

        let share = Scalar::from_slice(&raw_share)?;
        let commitments = accused_share
            .commitments
            .iter()
            .map(|c| Point::from_slice(c))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if V::verify(&reporter_index, &share, &commitments) {
            report.result = VerificationResult::ReporterPeerMalicious;
        } else {
            report.result = VerificationResult::ReportedPeerMalicious;
        }

        Ok(())
    }

    pub fn share(&self, index: u16) -> Result<&Shares> {
        self.pairs.get(&index).ok_or(Error::ShareNotFound(index))
    }

    pub fn own_share_clone(&self) -> Option<Vec<u8>> {
        self.own_share.clone()
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
}

fn is_share_matching(
    raw_share: &[u8],
    encrypted_share: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    let expected_encrypted_share = public_key.encrypt(raw_share)?;
    Ok(encrypted_share == expected_encrypted_share)
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
            is_output: HashSet::new(),
            waiting_own_share: HashSet::new(),
        }
    }

    pub fn add_event<V: Vss>(
        &mut self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        shares: Shares,
    ) -> Result<()> {
        if self.invalid_peers.contains(&source) || !self.peers.contains(&source) {
            return Ok(());
        }

        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        if shares.verify::<V>(&self.own_index, &self.secret_key)? {
            let index = self
                .peer_index(source)
                .expect("unrechable: index not found");
            let event = self.events.entry(id).or_insert(Event::new(self.own_peer));
            event.add_pair(index, shares);
        } else {
            self.invalid_peers.insert(source);
        }

        Ok(())
    }

    /// Set own share for the event
    ///
    /// If id in `waiting_own_share`, it will be removed from the set and return it
    pub fn set_own_share(&mut self, id: Vec<u8>, own_share: Vec<u8>) -> Result<Option<Vec<u8>>> {
        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        if self.waiting_own_share.remove(&id) {
            return Ok(Some(own_share));
        }

        let event = self.events.entry(id).or_insert(Event::new(self.own_peer));
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
        if self.invalid_peers.contains(&reporter) || self.invalid_peers.contains(&reported) {
            return Ok(());
        }

        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        self.peer_index(reporter)?;
        self.peer_index(reported)?;

        let event = self
            .events
            .entry(id.clone())
            .or_insert(Event::new(self.own_peer));
        event.add_report(reporter, reported)?;

        Ok(())
    }

    pub fn get_pending_reports_against_self(&self, id: &[u8]) -> Vec<libp2p::PeerId> {
        if let Some(event) = self.events.get(id) {
            event.pending_reports_against_self()
        } else {
            Vec::new()
        }
    }

    pub fn mark_self_report_as_responded(
        &mut self,
        id: &[u8],
        reporter: &libp2p::PeerId,
    ) -> Result<()> {
        let event = self.events.get_mut(id).ok_or(Error::EventNotFound(
            String::from_utf8_lossy(id).to_string(),
        ))?;

        event.mark_self_report_as_responded(reporter);
        Ok(())
    }

    pub fn add_report_response<V: Vss>(
        &mut self,
        id: Vec<u8>,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Vec<u8>,
    ) -> Result<()> {
        if self.invalid_peers.contains(&reporter) || self.invalid_peers.contains(&reported) {
            return Ok(());
        }

        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        if !self.events.contains_key(&id) {
            return Err(Error::EventNotFound(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        let reporter_index = self.peer_index(reporter)?;
        let reported_index = self.peer_index(reported)?;
        let reporter_public_key = self.peer_public_key_clone(&reporter)?;

        let event = self
            .events
            .get_mut(&id)
            .expect("unreachable: event not found");
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

    fn peer_public_key_clone(&self, peer: &libp2p::PeerId) -> Result<PublicKey> {
        self.peers
            .get_public_key_by_peer_id(peer)
            .cloned()
            .ok_or(Error::PeerNotFound(*peer))
    }

    pub fn output(&mut self, id: Vec<u8>) -> Result<EventResult> {
        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        let event = self.events.remove(&id).ok_or(Error::EventNotFound(
            String::from_utf8_lossy(&id).to_string(),
        ))?;

        let mut malicious_peers = event.get_malicious_peers();

        malicious_peers.extend(&self.invalid_peers);

        self.invalid_peers.extend(malicious_peers.iter());

        if !malicious_peers.is_empty() {
            self.is_output.insert(id);
            return Ok(EventResult::Failure {
                invalid_peers: malicious_peers,
            });
        }

        let mut shares_map = HashMap::new();
        for (peer, index) in &self.peers {
            if let Ok(shares) = event.share(index) {
                shares_map.insert(peer, shares.clone());
            }
        }

        self.is_output.insert(id);

        Ok(EventResult::Success {
            own_index: self.own_index,
            shares: shares_map,
        })
    }

    pub fn own_share_clone(&mut self, id: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.is_output.contains(id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(id).to_string(),
            ));
        }

        let event = match self.events.get(id) {
            Some(event) => event,
            None => {
                self.events.insert(id.to_vec(), Event::new(self.own_peer));
                return Ok(None);
            }
        };

        Ok(event.own_share_clone())
    }

    pub fn active_event_ids(&self) -> Vec<Vec<u8>> {
        self.events.keys().cloned().collect()
    }

    pub fn get_reporters_of(&self, id: &[u8], reported: libp2p::PeerId) -> Vec<libp2p::PeerId> {
        if let Some(event) = self.events.get(id) {
            let mut reporters = Vec::new();
            for (reporter, reported_peer) in event.reports.keys() {
                if *reported_peer == reported {
                    reporters.push(*reporter);
                }
            }
            reporters
        } else {
            Vec::new()
        }
    }
}
