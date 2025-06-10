use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{
    ec::hash_to_curve::{self, HashToCurve},
    traits::hasher::Hasher,
};

mod challenge_generator;
mod nonce_generator;

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Proof<C: hash_to_curve::Config> {
    #[serde(
        serialize_with = "serialize_affine",
        deserialize_with = "deserialize_affine"
    )]
    pub gamma: Affine<C>,
    pub c: C::ScalarField,
    pub s: C::ScalarField,
}

pub trait VrfConfig: hash_to_curve::Config {
    const SUITE_STRING: &'static [u8];
    const AFFINE_SIZE: usize;
    const SCALAR_SIZE: usize;
    const COFACTOR_SCALAR: Self::ScalarField;
}

#[allow(dead_code)]
pub fn prove<C: VrfConfig>(sk: C::ScalarField, alpha: &[u8]) -> Proof<C> {
    let y = (C::GENERATOR * sk).into_affine();
    let h = C::hash_to_curve(alpha);
    let gamma = (h * sk).into_affine();

    let k = nonce_generator::generate_nonce::<C::Hasher, C::ScalarField>(sk, alpha);

    let c = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>(
        C::SUITE_STRING,
        [y, h, gamma, (C::GENERATOR * k).into(), (h * k).into()],
    );

    let s = k + c * sk;

    Proof { gamma, c, s }
}

#[allow(dead_code)]
pub fn verify<C: VrfConfig>(pk: Affine<C>, alpha: &[u8], proof: &Proof<C>) -> bool {
    let h = C::hash_to_curve(alpha);
    let u = C::GENERATOR * proof.s - pk * proof.c;
    let v = h * proof.s - proof.gamma * proof.c;
    let c_prime = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>(
        C::SUITE_STRING,
        [pk, h, proof.gamma, u.into(), v.into()],
    );

    proof.c == c_prime
}

#[allow(dead_code)]
pub fn proof_to_hash<C: VrfConfig>(proof: &Proof<C>) -> Vec<u8> {
    const DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
    const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(C::SUITE_STRING);
    bytes.push(DOMAIN_SEPARATOR_FRONT);
    bytes.extend_from_slice((proof.gamma * C::COFACTOR_SCALAR).to_string().as_bytes());
    bytes.push(DOMAIN_SEPARATOR_BACK);

    C::Hasher::hash(&bytes)
}

fn serialize_affine<S: Serializer>(
    point: &impl AffineRepr,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut bytes = vec![0u8; point.compressed_size()];
    point
        .serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_bytes(&bytes)
}

fn deserialize_affine<'de, D: Deserializer<'de>, C: SWCurveConfig>(
    deserializer: D,
) -> Result<Affine<C>, D::Error> {
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    Affine::<C>::deserialize_compressed(bytes.as_slice())
        .map_err(|e| serde::de::Error::custom(e.to_string()))
}
