use std::collections::HashMap;

use crate::crypto::keypair::{PublicKey, ResidentSignature, VrfProof};

#[derive(Debug)]
pub struct SignedResult<T> {
    pub result: T,
    pub members: HashMap<PublicKey, (VrfProof, ResidentSignature)>,
}
