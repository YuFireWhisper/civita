use std::fmt::Debug;

use ark_ec::{short_weierstrass::Affine, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    crypto::{
        ec::{
            hash_to_curve::{self, HashToCurve},
            secret_key::SecretKey,
        },
        traits::{
            self,
            hasher::{Hasher, Multihash},
            vrf::{Prover, VerifyProof},
            SecretKey as _,
        },
        Error as CryptoError,
    },
    traits::serializable::{ConstantSize, Error as SerializableError, Serializable},
};

mod challenge_generator;
mod nonce_generator;
mod suites;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Proof<P, S> {
    pub gamma: P,
    pub c: S,
    pub s: S,
}

pub trait Cofactor: PrimeField {
    const COFACTOR_SCALAR: Self;
}

impl<C> traits::vrf::Proof for Proof<Affine<C>, C::ScalarField>
where
    C: hash_to_curve::Config,
    C::ScalarField: Cofactor,
{
    fn proof_to_hash(&self) -> Multihash {
        const DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
        const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        let mut bytes = Vec::new();
        bytes.push(DOMAIN_SEPARATOR_FRONT);
        bytes.extend_from_slice(
            (self.gamma * C::ScalarField::COFACTOR_SCALAR)
                .to_string()
                .as_bytes(),
        );
        bytes.push(DOMAIN_SEPARATOR_BACK);

        C::Hasher::hash(&bytes)
    }
}

impl<P, S> Serializable for Proof<P, S>
where
    P: CanonicalSerialize + CanonicalDeserialize,
    S: CanonicalSerialize + CanonicalDeserialize,
{
    fn serialized_size(&self) -> usize {
        self.gamma.compressed_size() + self.c.compressed_size() + self.s.compressed_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, SerializableError> {
        let gamma = P::deserialize_compressed(reader.by_ref())?;
        let c = S::deserialize_compressed(reader.by_ref())?;
        let s = S::deserialize_compressed(reader.by_ref())?;

        Ok(Self { gamma, c, s })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), SerializableError> {
        self.gamma.serialize_compressed(writer.by_ref())?;
        self.c.serialize_compressed(writer.by_ref())?;
        self.s.serialize_compressed(writer.by_ref())?;

        Ok(())
    }
}

impl<C> ConstantSize for Proof<Affine<C>, C::ScalarField>
where
    C: hash_to_curve::Config,
    C::ScalarField: Cofactor,
{
    const SIZE: usize =
        Affine::<C>::SIZE + 2 * (C::ScalarField::MODULUS_BIT_SIZE as usize / 8usize);
}

impl<C> Prover for SecretKey<C>
where
    C: hash_to_curve::Config,
    C::ScalarField: Cofactor,
{
    type Proof = Proof<Affine<C>, C::ScalarField>;

    fn prove(&self, alpha: &[u8]) -> Result<Proof<Affine<C>, C::ScalarField>, CryptoError> {
        let y = self.public_key();
        let h = C::hash_to_curve(alpha);
        let gamma = (h * self.sk).into_affine();
        let k = nonce_generator::generate_nonce::<C::Hasher, _>(self.sk, alpha);
        let c = challenge_generator::generate_challenge::<_, C::Hasher>([
            y,
            h,
            gamma,
            (C::GENERATOR * k).into(),
            (h * k).into(),
        ])?;

        let s = k + c * self.sk;

        Ok(Proof { gamma, c, s })
    }
}

impl<C> VerifyProof for Affine<C>
where
    C: hash_to_curve::Config,
    C::ScalarField: Cofactor,
{
    type Proof = Proof<Affine<C>, C::ScalarField>;

    fn verify_proof(&self, alpha: &[u8], proof: &Self::Proof) -> Result<(), CryptoError> {
        let h = C::hash_to_curve(alpha);
        let u = C::GENERATOR * proof.s - *self * proof.c;
        let v = h * proof.s - proof.gamma * proof.c;
        let c_prime = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>([
            *self,
            h,
            proof.gamma,
            u.into(),
            v.into(),
        ])?;

        if proof.c != c_prime {
            Err(CryptoError::VrfVerificationFailed)
        } else {
            Ok(())
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use ark_ff::MontFp;
//     use ark_secp256r1::{Affine, Fq, Fr};
//
//     use crate::crypto::traits::vrf::{Proof, Prover, VerifyProof};
//
//     const SK: Fr =
//         MontFp!("91225253027397101270059260515990221874496108017261222445699397644687913215777");
//     const PK_X: Fq = MontFp!("0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
//     const PK_Y: Fq = MontFp!("0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
//
//     #[rstest::rstest]
//     #[case("sample")]
//     #[case("abc")]
//     #[case("abcdef0123456789")]
//     #[test]
//     fn corrent_value(#[case] alpha: &str) {
//         use crate::crypto::ec::secret_key::SecretKey;
//
//         let pk = Affine::new(PK_X, PK_Y);
//
//         let sk = SecretKey::new(SK);
//         let proof = sk.prove(alpha.as_bytes()).unwrap();
//
//         let is_valid = pk.verify_proof(alpha.as_bytes(), &proof);
//         let should_invalid = pk.verify_proof(b"invalid", &proof);
//
//         let mut bytes = Vec::new();
//         proof.to_writer(&mut bytes);
//
//         let deserialized = super::Proof::<Affine, Fr>::from_reader(&mut bytes.as_slice());
//
//         assert!(is_valid.is_ok());
//         assert!(should_invalid.is_err());
//         assert_eq!(proof, deserialized.unwrap());
//     }
// }
