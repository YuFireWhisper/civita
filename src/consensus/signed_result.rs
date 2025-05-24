use std::collections::HashMap;

use crate::crypto::keypair::{PublicKey, ResidentSignature, VrfProof};

pub struct SignedResult<T> {
    pub result: T,
    pub members: HashMap<PublicKey, (VrfProof, ResidentSignature)>,
}
