use std::collections::HashMap;

use crate::{
    constants::HashArray,
    crypto::keypair::{PublicKey, ResidentSignature, VrfProof},
};

#[derive(Debug)]
pub struct SignatureCollector {
    final_hash: HashArray,
    signatures: HashMap<PublicKey, (VrfProof, ResidentSignature)>,
}

impl SignatureCollector {
    pub fn new(hash: HashArray) -> Self {
        Self {
            final_hash: hash,
            signatures: HashMap::new(),
        }
    }

    pub fn add_signature(
        &mut self,
        public_key: PublicKey,
        proof: VrfProof,
        signature: ResidentSignature,
    ) {
        if !public_key.verify_signature(self.final_hash, &signature) {
            return;
        }

        self.signatures.insert(public_key, (proof, signature));
    }

    pub fn get_signatures(&mut self) -> HashMap<PublicKey, (VrfProof, ResidentSignature)> {
        std::mem::take(&mut self.signatures)
    }
}
