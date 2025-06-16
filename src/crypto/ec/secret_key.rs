use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use rand::Rng;

use crate::crypto::{self, traits};

#[derive(Debug)]
pub struct SecretKey<C: SWCurveConfig> {
    pub(crate) sk: C::ScalarField,
    pub(crate) pk: Affine<C>,
}

impl<C: SWCurveConfig> SecretKey<C> {
    pub fn new(sk: C::ScalarField) -> Self {
        let pk = (C::GENERATOR * sk).into_affine();
        SecretKey { sk, pk }
    }
}

impl<C: SWCurveConfig> traits::SecretKey for SecretKey<C> {
    type PublicKey = Affine<C>;

    fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        let sk = C::ScalarField::from_be_bytes_mod_order(&bytes);
        SecretKey::new(sk)
    }

    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error> {
        Ok(Self::from(slice))
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.into()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        self.pk
    }
}

impl<C: SWCurveConfig> Clone for SecretKey<C> {
    fn clone(&self) -> Self {
        SecretKey {
            sk: self.sk,
            pk: self.pk,
        }
    }
}

impl<C: SWCurveConfig> PartialEq for SecretKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.sk == other.sk && self.pk == other.pk
    }
}

impl<C: SWCurveConfig> Eq for SecretKey<C> {}

impl<C: SWCurveConfig> From<SecretKey<C>> for Vec<u8> {
    fn from(value: SecretKey<C>) -> Self {
        (&value).into()
    }
}

impl<C: SWCurveConfig> From<&SecretKey<C>> for Vec<u8> {
    fn from(sk: &SecretKey<C>) -> Self {
        let mut bytes = Vec::with_capacity(sk.sk.compressed_size());
        sk.sk
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize secret key");
        bytes
    }
}

impl<C: SWCurveConfig> From<&[u8]> for SecretKey<C> {
    fn from(slice: &[u8]) -> Self {
        let sk = C::ScalarField::from_be_bytes_mod_order(slice);
        SecretKey::new(sk)
    }
}
