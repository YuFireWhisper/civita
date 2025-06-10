use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, traits};

#[derive(Clone)]
#[derive(Debug)]
pub struct PublicKey<C: SWCurveConfig>(pub(crate) Affine<C>);

impl<C: SWCurveConfig> traits::PublicKey for PublicKey<C> {
    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error> {
        Affine::<C>::deserialize_compressed(slice)
            .map(PublicKey)
            .map_err(crypto::Error::from)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.0.compressed_size());
        self.0
            .serialize_compressed(&mut bytes)
            .expect("Serialization should not fail");
        bytes
    }
}

impl<C: SWCurveConfig> Serialize for PublicKey<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::crypto::traits::PublicKey;
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl<'de, C: SWCurveConfig> Deserialize<'de> for PublicKey<C> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        Affine::<C>::deserialize_compressed(bytes.as_slice())
            .map(PublicKey)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}
