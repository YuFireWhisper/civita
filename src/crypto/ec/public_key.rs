use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    crypto::traits::PublicKey,
    traits::serializable::{ConstantSize, Error, Serializable},
};

impl<C: SWCurveConfig> Serializable for Affine<C> {
    fn serialized_size(&self) -> usize {
        self.compressed_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, Error> {
        Self::deserialize_compressed(reader).map_err(Error::from)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.serialize_compressed(writer)
            .expect("Failed to serialize Affine point");
    }
}

impl<C: SWCurveConfig> ConstantSize for Affine<C> {
    const SIZE: usize = 1 + C::ScalarField::MODULUS_BIT_SIZE as usize / 8usize;
}

impl<C: SWCurveConfig> PublicKey for Affine<C> {}
