use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use rand::Rng;

use crate::{
    crypto::traits,
    traits::serializable::{Error, Serializable},
};

#[derive(Derivative)]
#[derivative(Clone(bound = ""), Copy(bound = ""))]
#[derivative(Debug(bound = ""))]
#[derivative(Eq(bound = ""), PartialEq(bound = ""))]
#[derivative(Hash(bound = ""))]
pub struct SecretKey<C: SWCurveConfig> {
    pub(crate) sk: C::ScalarField,
    pub(crate) pk: Affine<C>,
}

impl<C: SWCurveConfig> SecretKey<C> {
    pub fn new(sk: C::ScalarField) -> Self {
        let pk = (C::GENERATOR * sk).into_affine();
        Self { sk, pk }
    }
}

impl<C: SWCurveConfig> Serializable for SecretKey<C> {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, Error> {
        let sk =
            C::ScalarField::deserialize_compressed(reader).map_err(|e| Error(e.to_string()))?;
        Ok(Self::new(sk))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.sk
            .serialize_compressed(writer)
            .expect("Failed to serialize SecretKey");
    }
}

impl<C: SWCurveConfig> traits::SecretKey for SecretKey<C> {
    type PublicKey = Affine<C>;

    fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Self::new(C::ScalarField::from_be_bytes_mod_order(&bytes))
    }

    fn public_key(&self) -> Self::PublicKey {
        self.pk
    }
}
