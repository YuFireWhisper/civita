use serde::{Deserialize, Serialize};

use crate::crypto::traits::{public_key::PublicKey, secret_key::SecretKey, signature::Signature};

pub trait Suite {
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;
    type Signature: Signature;
    type VrfProof: Serialize + for<'a> Deserialize<'a>;
}
