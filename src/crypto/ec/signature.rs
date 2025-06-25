use std::fmt::Debug;

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

use crate::{
    crypto::{
        ec::secret_key::SecretKey,
        traits::{self, suite::HasherConfig, SecretKey as _},
        Error as CryptoError, Hasher,
    },
    traits::serializable::{ConstantSize, Error as SerializableError, Serializable},
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Signature<P, S> {
    pub r: P,
    pub s: S,
}

impl<P, S> Serializable for Signature<P, S>
where
    P: CanonicalSerialize + CanonicalDeserialize,
    S: CanonicalSerialize + CanonicalDeserialize,
{
    fn serialized_size(&self) -> usize {
        self.r.compressed_size() + self.s.compressed_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, SerializableError> {
        let r = P::deserialize_compressed(reader.by_ref())?;
        let s = S::deserialize_compressed(reader.by_ref())?;

        Ok(Self { r, s })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), SerializableError> {
        self.r.serialize_compressed(writer.by_ref())?;
        self.s.serialize_compressed(writer.by_ref())?;

        Ok(())
    }
}

impl<C: SWCurveConfig + HasherConfig> ConstantSize for Signature<Affine<C>, C::ScalarField> {
    const SIZE: usize = Affine::<C>::SIZE + C::ScalarField::MODULUS_BIT_SIZE as usize / 8usize;
}

impl<C: SWCurveConfig + HasherConfig> traits::Signature for Signature<Affine<C>, C::ScalarField> {}

impl<C: SWCurveConfig + HasherConfig> traits::Signer for SecretKey<C> {
    type Signature = Signature<Affine<C>, C::ScalarField>;

    fn sign(&self, msg: &[u8]) -> Result<Signature<Affine<C>, C::ScalarField>, CryptoError> {
        let mut random = [0u8; 32];
        rand::rng().fill(&mut random);

        let k = C::ScalarField::from_be_bytes_mod_order(&random);
        let r = C::GENERATOR * k;
        let e = generate_challenge::<_, _, C::ScalarField, C::Hasher>(msg, r, &self.public_key())?;
        let s = k + e * self.sk;

        Ok(Signature {
            r: r.into_affine(),
            s,
        })
    }
}

impl<C: SWCurveConfig + HasherConfig> traits::VerifiySignature for Affine<C> {
    type Signature = Signature<Affine<C>, C::ScalarField>;

    fn verify_signature(
        &self,
        msg: &[u8],
        sig: &Signature<Affine<C>, C::ScalarField>,
    ) -> Result<(), CryptoError> {
        let e = generate_challenge::<_, _, C::ScalarField, C::Hasher>(msg, sig.r, self)?;

        let lhs = C::GENERATOR * sig.s;
        let rhs = sig.r + *self * e;

        if lhs != rhs.into_affine() {
            Err(CryptoError::SignatureVerificationFailed)
        } else {
            Ok(())
        }
    }
}

fn generate_challenge<P1: CanonicalSerialize, P2: CanonicalSerialize, S: PrimeField, H: Hasher>(
    msg: &[u8],
    r: P1,
    pk: &P2,
) -> Result<S, CryptoError> {
    let mut bytes = Vec::with_capacity(msg.len() + r.compressed_size() + pk.compressed_size());

    bytes.extend_from_slice(msg);
    r.serialize_compressed(&mut bytes)?;
    pk.serialize_compressed(&mut bytes)?;

    Ok(S::from_be_bytes_mod_order(H::hash(&bytes).digest()))
}

#[cfg(test)]
mod tests {
    use crate::crypto::traits::VerifiySignature;

    use super::*;

    use ark_ff::MontFp;
    use ark_secp256r1::{Affine, Fq, Fr};

    const SK: Fr =
        MontFp!("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    const PK_X: Fq = MontFp!("0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    const PK_Y: Fq = MontFp!("0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");

    #[rstest::rstest]
    #[case(b"sample")]
    #[case(b"another message")]
    #[case(b"123")]
    fn correct_signature(#[case] msg: &[u8]) {
        use crate::crypto::traits::Signer;

        let sk = SecretKey::new(SK);
        let pk = Affine::new(PK_X, PK_Y);

        let sig = sk.sign(msg).unwrap();

        let should_valid = pk.verify_signature(msg, &sig);
        let should_invalid = pk.verify_signature(b"wrong message", &sig);

        assert!(should_valid.is_ok(), "Signature should be valid");
        assert!(should_invalid.is_err(), "Signature should be invalid");
    }
}
