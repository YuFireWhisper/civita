use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResidentStatus {
    Joining,
    Active,
    Probation,
    Offline,
    Banned,
}
