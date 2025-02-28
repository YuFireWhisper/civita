use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaliciousBehavior {
    DoubleSpending,
    DoubleVoting,
    InvalidSignature,
    DataTampering,
    InvalidVRFProof,
    UnresponsiveCommittee,
}
