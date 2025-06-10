use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr,
};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(point: &impl AffineRepr, serializer: S) -> Result<S::Ok, S::Error> {
    let mut bytes = vec![0u8; point.compressed_size()];
    point
        .serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize<'de, D: Deserializer<'de>, C: SWCurveConfig>(
    deserializer: D,
) -> Result<Affine<C>, D::Error> {
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    Affine::<C>::deserialize_compressed(bytes.as_slice())
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}
