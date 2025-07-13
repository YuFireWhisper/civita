use std::fmt::Debug;

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use civita_serialize_derive::Serialize;
use rand::Rng;

use crate::crypto::{
    ec::{secret_key::SecretKey, HasherConfig},
    traits::{self, SecretKey as _},
    Hasher,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
#[derive(Serialize)]
pub struct Signature<P, S> {
    pub r: P,
    pub s: S,
}

impl<C: SWCurveConfig + HasherConfig> traits::Signer for SecretKey<C> {
    type Signature = Signature<Affine<C>, C::ScalarField>;

    fn sign(&self, msg: &[u8]) -> Signature<Affine<C>, C::ScalarField> {
        let mut random = [0u8; 32];
        rand::rng().fill(&mut random);

        let k = C::ScalarField::from_be_bytes_mod_order(&random);
        let r = C::GENERATOR * k;
        let e = generate_challenge::<_, _, C::ScalarField, C::Hasher>(msg, r, &self.public_key());
        let s = k + e * self.sk;

        Signature {
            r: r.into_affine(),
            s,
        }
    }
}

impl<C: SWCurveConfig + HasherConfig> traits::VerifiySignature for Affine<C> {
    type Signature = Signature<Affine<C>, C::ScalarField>;

    fn verify_signature(&self, msg: &[u8], sig: &Signature<Affine<C>, C::ScalarField>) -> bool {
        let e = generate_challenge::<_, _, C::ScalarField, C::Hasher>(msg, sig.r, self);

        let lhs = C::GENERATOR * sig.s;
        let rhs = sig.r + *self * e;

        lhs == rhs.into_affine()
    }
}

fn generate_challenge<P1: CanonicalSerialize, P2: CanonicalSerialize, S: PrimeField, H: Hasher>(
    msg: &[u8],
    r: P1,
    pk: &P2,
) -> S {
    let mut bytes = Vec::with_capacity(msg.len() + r.compressed_size() + pk.compressed_size());

    bytes.extend_from_slice(msg);
    r.serialize_compressed(&mut bytes)
        .expect("Failed to serialize r");
    pk.serialize_compressed(&mut bytes)
        .expect("Failed to serialize public key");

    S::from_be_bytes_mod_order(H::hash(&bytes).digest())
}
