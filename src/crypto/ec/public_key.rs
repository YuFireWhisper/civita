use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::crypto::{self, traits};

impl<C: SWCurveConfig> traits::PublicKey for Affine<C> {
    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error> {
        Self::deserialize_compressed(slice).map_err(crypto::Error::from)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.compressed_size());
        self.serialize_compressed(&mut bytes)
            .expect("Failed to serialize public key");
        bytes
    }
}
