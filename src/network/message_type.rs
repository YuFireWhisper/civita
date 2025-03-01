use serde::{Deserialize, Serialize};

use crate::resident::{
    malicious_behaviour::MaliciousBehavior, requation_action::ReputationAction,
    resident_id::ResidentId, resident_status::ResidentStatus,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    JoinRequest {
        resident_id: ResidentId,
        public_key: Vec<u8>,
    },
    JoinResponse {
        community_id: String,
        committee_members: Vec<String>,
        chairpersons: Vec<String>,
    },
    Heartbeat {
        resident_id: ResidentId,
        timestamp: u64,
        status: ResidentStatus,
    },
    CommitteeElection {
        round: u64,
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
    },
    ProposalSubmission {
        proposal_id: String,
        content: Vec<u8>,
        proposal_type: String,
    },
    ProposalVote {
        proposal_id: String,
        approve: bool,
    },
    ReputationUpdate {
        resident_id: ResidentId,
        reputation: u64,
        action: ReputationAction,
    },
    MaliciousReport {
        reported_id: String,
        behavior: MaliciousBehavior,
        evidence: Vec<u8>,
    },
    FindPeerRequest {
        target_peer_id: String,
    },
    FindPeerResponse {
        target_peer_id: String,
        addresses: Vec<String>,
    },
}
