use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::crypto::dkg::classic::signature::SignatureBytes;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Encode, Decode)]
#[derive(Serialize, Deserialize)]
pub enum Data {
    Classic(SignatureBytes),
}

pub trait Scheme {
    type Error;
    type Keypair;

    fn sign(
        seed: &[u8],
        message: &[u8],
        keypair: &Self::Keypair,
    ) -> Result<Data, Self::Error>;
}

impl Data {
    pub fn validate(&self, message: &[u8], keypair: &[u8]) -> bool {
        match self {
            Data::Classic(sig) => sig.validate(message, keypair),
        }
    }
}
