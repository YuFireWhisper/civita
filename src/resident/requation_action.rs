use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationAction {
    SuccessfulProposal,
    CorrectVote,
    IncorrectVote,
    OnlineAvailability,
    MaliciousBehavior,
    SuccessfulValidation,
}
