use serde::{Deserialize, Serialize};

use crate::committee;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
enum Type {
    Resident,
    Proposal,
    CommitteeInfo,
    CurrentCommitteeInfo,
    Raw,
}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum Payload {
    Resident { cehdit: u64, custom: Vec<u8> },
    Proposal(Vec<u8>),
    CommitteeInfo(committee::Info),
    CurrentCommitteeInfo(committee::Info),
    Raw(Vec<u8>),
}
