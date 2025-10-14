use bincode::serde::encode_into_std_write;
use serde::{Deserialize, Serialize};

use crate::{
    ty::token::{ScriptPk, Token, Value},
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

impl Command {
    pub fn new(code: u8, inputs: Vec<Input>, outputs: Vec<(Value, ScriptPk)>) -> Self {
        debug_assert!(outputs.len() <= u32::MAX as usize);

        let outputs = outputs
            .into_iter()
            .enumerate()
            .map(|(index, (value, script_pk))| Token {
                atom_id: Default::default(),
                index: index as u32,
                value,
                script_pk,
            })
            .collect();

        Self {
            code,
            inputs,
            outputs,
        }
    }

    pub fn to_no_outputs_atom_id_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_into_std_write(&self.inputs, &mut buf, BINCODE_CONFIG).unwrap();

        for output in &self.outputs {
            buf.extend(&output.index.to_be_bytes());
            buf.extend(&output.value);
            buf.extend(&output.script_pk);
        }

        buf
    }
}
