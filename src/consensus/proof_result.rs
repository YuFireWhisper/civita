use crate::crypto::keypair::{PublicKey, VrfProof};

pub struct ProofResult<T> {
    pub result: T,
    pub proof: Vec<(VrfProof, PublicKey)>,
}
