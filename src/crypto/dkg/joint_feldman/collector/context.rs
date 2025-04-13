use std::collections::{HashMap, HashSet};

use crate::crypto::{
    dkg::joint_feldman::peer_info::PeerInfo,
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::element::{Public, Secret},
        vss::{Shares, SharesError, Vss},
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Shares(#[from] SharesError),

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
    ReportNotFound(libp2p::PeerId, libp2p::PeerId),

    #[error("Report already exists for reporter {0} against reported {1}")]
    ReportAlreadyExists(libp2p::PeerId, libp2p::PeerId),
}

#[derive(Debug)]
pub struct EventOutput {
    pub invalid_peers: HashSet<libp2p::PeerId>,
    // If invalid_peers isn's empty, shares will be None
    pub shares: Option<HashMap<libp2p::PeerId, Shares>>,
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
#[derive(Default)]
pub struct Event {
    pairs: HashMap<u16, Shares>,
    own_share: Option<Vec<u8>>,
    reports: HashMap<(libp2p::PeerId, libp2p::PeerId), Report>,
}

#[derive(Debug)]
pub struct Context {
    peers: HashMap<libp2p::PeerId, PeerInfo>,
    invalid_peers: HashSet<libp2p::PeerId>,
    secret_key: SecretKey,
    own_index: u16,
    events: HashMap<Vec<u8>, Event>,
    is_output: HashSet<Vec<u8>>,
}

impl Event {
    pub fn add_pair(&mut self, source_index: u16, shares: Shares) {
        self.pairs.insert(source_index, shares);
    }

    pub fn set_own_share(&mut self, own_share: Vec<u8>) {
        self.own_share = Some(own_share);
    }

    pub fn add_report(&mut self, reporter: libp2p::PeerId, reported: libp2p::PeerId) -> Result<()> {
        let key = (reporter, reported);
        if self.reports.contains_key(&key) {
            return Err(Error::ReportAlreadyExists(reporter, reported));
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

        Ok(())
    }

    pub fn respond_to_report<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &mut self,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Vec<u8>,
        reporter_index: u16,
        reported_index: u16,
        reporter_public_key: &PublicKey,
    ) -> Result<()> {
        let key = (reporter, reported);
        let report = self
            .reports
            .get_mut(&key)
            .ok_or(Error::ReportNotFound(reporter, reported))?;

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

        let share = SK::from_bytes(&raw_share);
        let commitments: Vec<_> = accused_share
            .commitments
            .iter()
            .map(|c| PK::from_bytes(c))
            .collect();

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

    pub fn peer_count(&self) -> usize {
        self.pairs.len()
    }

    pub fn own_share(&self) -> Option<&[u8]> {
        self.own_share.as_deref()
    }

    pub fn get_malicious_peers(&self) -> HashSet<libp2p::PeerId> {
        let mut malicious = HashSet::new();

        for (_, report) in &self.reports {
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
    Ok(encrypted_share == &expected_encrypted_share)
}

impl Context {
    pub fn new(
        peers: HashMap<libp2p::PeerId, PeerInfo>,
        secret_key: SecretKey,
        own_peer: libp2p::PeerId,
    ) -> Self {
        let own_index = peers
            .get(&own_peer)
            .expect("Own peer not found in the list")
            .index;

        Self {
            peers,
            invalid_peers: HashSet::new(),
            secret_key,
            own_index,
            events: HashMap::new(),
            is_output: HashSet::new(),
        }
    }

    pub fn add_event<SK: Secret, PK: Public, V: Vss<SK, PK>>(
        &mut self,
        id: Vec<u8>,
        source: libp2p::PeerId,
        shares: Shares,
    ) -> Result<()> {
        if self.invalid_peers.contains(&source) || !self.peers.contains_key(&source) {
            return Ok(());
        }

        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        if shares.verify::<SK, PK, V>(&self.own_index, &self.secret_key)? {
            let index = self
                .peer_index(source)
                .expect("unrechable: index not found");
            let event = self.events.entry(id).or_default();
            event.add_pair(index, shares);
        } else {
            self.invalid_peers.insert(source);
        }

        Ok(())
    }

    pub fn add_own_share(&mut self, id: Vec<u8>, own_share: Vec<u8>) -> Result<()> {
        if self.is_output.contains(&id) {
            return Err(Error::EventAlreadyOutput(
                String::from_utf8_lossy(&id).to_string(),
            ));
        }

        let event = self.events.entry(id).or_default();
        event.set_own_share(own_share);

        Ok(())
    }

    fn peer_index(&self, peer_id: libp2p::PeerId) -> Result<u16> {
        self.peers
            .get(&peer_id)
            .map(|peer| peer.index)
            .ok_or(Error::PeerNotFound(peer_id))
    }

    pub fn report_peer(
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

        let event = self.events.entry(id).or_default();
        event.add_report(reporter, reported)?;

        Ok(())
    }

    pub fn respond_to_report<SK: Secret, PK: Public, V: Vss<SK, PK>>(
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
        event.respond_to_report::<SK, PK, V>(
            reporter,
            reported,
            raw_share,
            reporter_index,
            reported_index,
            &reporter_public_key,
        )?;

        Ok(())
    }

    fn peer_public_key(&self, peer: &libp2p::PeerId) -> Result<&PublicKey> {
        self.peers
            .get(peer)
            .map(|peer_info| &peer_info.public_key)
            .ok_or(Error::PeerNotFound(*peer))
    }

    fn peer_public_key_clone(&self, peer: &libp2p::PeerId) -> Result<PublicKey> {
        self.peers
            .get(peer)
            .map(|peer_info| peer_info.public_key.clone())
            .ok_or(Error::PeerNotFound(*peer))
    }

    pub fn output(&mut self, id: Vec<u8>) -> Result<EventOutput> {
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
            return Ok(EventOutput {
                invalid_peers: malicious_peers,
                shares: None,
            });
        }

        let mut shares_map = HashMap::new();
        for (peer_id, peer_info) in &self.peers {
            if let Ok(shares) = event.share(peer_info.index) {
                shares_map.insert(*peer_id, shares.clone());
            }
        }

        self.is_output.insert(id);

        Ok(EventOutput {
            invalid_peers: HashSet::new(),
            shares: Some(shares_map),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{dkg::joint_feldman::collector::context::Event, primitives::vss::Shares};

    #[test]
    fn length_up() {
        const NUMS: usize = 10;

        let mut event = Event::default();
        for i in 0..NUMS {
            event.add_pair(i as u16, Shares::empty());
            assert_eq!(event.pairs.len(), i + 1);
        }
    }
}
