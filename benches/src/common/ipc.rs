use std::str::FromStr;

use civita_core::consensus::graph::Status;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub id: usize,
    pub count: u64,
    pub status: Status,
}

impl Response {
    pub fn new(id: usize, count: u64, status: Status) -> Self {
        Self { id, count, status }
    }
}

impl std::fmt::Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self).map_err(|_| std::fmt::Error)?
        )
    }
}

impl FromStr for Response {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
