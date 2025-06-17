use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use rand::Rng;

use crate::crypto::{self, traits};

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""))]
#[derivative(Debug(bound = ""))]
#[derivative(Eq(bound = ""), PartialEq(bound = ""))]
pub struct SecretKey<C: SWCurveConfig> {
    pub(crate) sk: C::ScalarField,
    pub(crate) pk: Affine<C>,
}

impl<C: SWCurveConfig> SecretKey<C> {
    pub fn new(scalar: C::ScalarField) -> Self {
        let pk = (C::GENERATOR * scalar).into_affine();
        Self { sk: scalar, pk }
    }
}

impl<C: SWCurveConfig> traits::SecretKey for SecretKey<C> {
    type PublicKey = Affine<C>;

    fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Self::new(C::ScalarField::from_be_bytes_mod_order(&bytes))
    }

    fn from_slice(slice: &[u8]) -> Result<Self, crypto::Error> {
        let scalar = C::ScalarField::deserialize_compressed(slice)?;
        Ok(Self::new(scalar))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.sk.compressed_size());
        self.sk
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize secret key");
        bytes
    }

    fn public_key(&self) -> Self::PublicKey {
        self.pk
    }
}
