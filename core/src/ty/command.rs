use derivative::Derivative;
use multihash_derive::MultihashDigest;
use serde::{Deserialize, Serialize};

use crate::{crypto::Multihash, traits::Config, ty::token::Token, utils::mmr::MmrProof};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Input {
    pub token: Token,
    pub proof: MmrProof,
    pub sig: Vec<u8>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: Config", deserialize = "T: Config"))]
pub struct Command<T: Config> {
    pub code: u8,
    pub inputs: Vec<Input<T>>,
    pub outputs: Vec<Token<T>>,
}

impl<T: Config> Input<T> {
    pub fn id(&self) -> Multihash {
        use bincode::{config, serde::encode_to_vec};

        match self {
            Input::OnChain(_, id, _, _) => *id,
            Input::OffChain(_) => {
                T::HASHER.digest(&encode_to_vec(self, config::standard()).unwrap())
            }
        }
    }
}

impl<T: Config> Command<T> {
    pub fn new(code: u8, inputs: Vec<Input<T>>, outputs: Vec<Token<T>>) -> Self {
        Self {
            code,
            inputs,
            outputs,
        }
    }
}
