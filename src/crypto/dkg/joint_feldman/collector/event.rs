use std::collections::{HashMap, HashSet};

use crate::crypto::{
    keypair::{self, PublicKey, SecretKey},
    primitives::{
        algebra::{self, Point, Scalar},
        vss::{
            encrypted_share::{self, EncryptedShare},
            EncryptedShares,
        },
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Report already exists for reporter: {0}, reported: {1}")]
    ReportAlreadyExists(String, String),

    #[error("Report not found")]
    ReportNotFound,

    #[error("Share not found for index: {0}")]
    ShareNotFound(u16),

    #[error("Algebra error: {0}")]
    Algebra(#[from] algebra::Error),

    #[error("Encrypted share error: {0}")]
    EncryptedShare(#[from] encrypted_share::Error),

    #[error("Keypair error: {0}")]
    Keypair(#[from] keypair::Error),
}

pub enum EventResult {
    Success {
        bundle: HashMap<libp2p::PeerId, (Scalar, Vec<Point>)>,
    },
    Failure {
        invalid_peers: HashSet<libp2p::PeerId>,
    },
}

#[derive(Debug)]
pub struct Bundle {
    pub encrypted_shares: EncryptedShares,
    pub commitments: Vec<Point>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerificationResult {
    ReportedPeerMalicious,
    ReporterPeerMalicious,
    Pending,
}

#[derive(Debug)]
pub struct Report {
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
    pending_self_reports: HashSet<libp2p::PeerId>,
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

    pub fn respond_to_report(
        &mut self,
        reporter: libp2p::PeerId,
        reported: libp2p::PeerId,
        raw_share: Scalar,
        reporter_index: u16,
        reported_index: u16,
        reporter_public_key: &PublicKey,
    ) -> Result<()> {
        let key = (reporter, reported);
        let report = self.reports.get_mut(&key).ok_or(Error::ReportNotFound)?;

        report.raw_share = Some(raw_share.clone());

        let accused_share = self
            .pairs
            .get(&reported_index)
            .ok_or(Error::ShareNotFound(reported_index))?;

        Self::verify_and_update_report(
            report,
            &raw_share,
            accused_share,
            reporter_index,
            reporter_public_key,
        )?;

        Ok(())
    }

    fn verify_and_update_report(
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

        report.result =
            match reported_raw_share.verify(reporter_index, &reported_bundle.commitments)? {
                true => VerificationResult::ReporterPeerMalicious,
                false => VerificationResult::ReportedPeerMalicious,
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

    pub fn reports(&self) -> &HashMap<(libp2p::PeerId, libp2p::PeerId), Report> {
        &self.reports
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
