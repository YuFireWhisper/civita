use serde::{Deserialize, Serialize};

use crate::{ty::token::Token, utils::mmr::MmrProof};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Input {
    pub token: Token,
    pub proof: MmrProof,
    pub sig: Vec<u8>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Command {
    pub code: u8,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Token>,
}

impl Command {
    pub fn new(code: u8, inputs: Vec<Input>, outputs: Vec<Token>) -> Self {
        Self {
            code,
            inputs,
            outputs,
        }
    }
}
