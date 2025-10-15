use bincode::serde::encode_to_vec;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Hasher,
    ty::{token::Token, ScriptPk, Value},
    utils::mmr::MmrProof,
    BINCODE_CONFIG,
};

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

impl Input {
    pub fn new(token: Token, proof: MmrProof, sig: Vec<u8>) -> Self {
        Self { token, proof, sig }
    }
}

impl Command {
    pub fn new<T, U, I>(code: u8, inputs: Vec<Input>, outputs: I, hasher: Hasher) -> Self
    where
        T: Into<Value>,
        U: Into<ScriptPk>,
        I: IntoIterator<Item = (T, U)>,
    {
        let first_input_id = inputs
            .first()
            .map(|input| input.token.id(hasher))
            .unwrap_or_default();

        let outputs = outputs
            .into_iter()
            .enumerate()
            .map(|(index, (value, script_pk))| {
                Token::new(first_input_id, index as u32, value, script_pk)
            })
            .collect();

        Self {
            code,
            inputs,
            outputs,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode_to_vec(self, BINCODE_CONFIG).unwrap()
    }
}
