use ark_ec::{
    short_weierstrass::{Affine, Projective},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    self,
    ec::{
        base_config::BaseConfig, secret_key::SecretKey, serialize_affine,
        serialize_size::SerializeSize,
    },
    traits::{self, hasher::Hasher},
};

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Signature<C: BaseConfig + SerializeSize> {
    #[serde(with = "serialize_affine")]
    pub r: Affine<C>,
    pub s: C::ScalarField,
}

impl<C: BaseConfig + SerializeSize> traits::signature::Signature for Signature<C> {
    fn from_slice(bytes: &[u8]) -> Result<Self, crypto::Error> {
        let r_size = (C::ScalarField::MODULUS_BIT_SIZE.div_ceil(8) + 1) as usize;
        let s_size = C::ScalarField::MODULUS_BIT_SIZE.div_ceil(8) as usize;

        if bytes.len() != r_size + s_size {
            return Err(crate::crypto::Error::Serialization(
                "Invalid signature size".to_string(),
            ));
        }

        let r = Affine::<C>::deserialize_compressed(&bytes[..r_size])?;
        let s = C::ScalarField::from_be_bytes_mod_order(&bytes[r_size..]);

        Ok(Signature { r, s })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.r.compressed_size() + self.s.compressed_size());

        self.r
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize point");
        self.s
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize scalar");

        bytes
    }
}

impl<C: BaseConfig + SerializeSize> traits::Signer<Signature<C>> for SecretKey<C> {
    fn sign(&self, msg: &[u8]) -> Signature<C> {
        let mut random = [0u8; 32];
        rand::rng().fill(&mut random);

        let k = C::ScalarField::from_be_bytes_mod_order(&random);
        let r = C::GENERATOR * k;
        let e = generate_challenge(msg, r, &self.pk);
        let s = k + e * self.sk;

        Signature {
            r: r.into_affine(),
            s,
        }
    }
}

impl<C: BaseConfig + SerializeSize> traits::VerifiySignature<Signature<C>> for Affine<C> {
    fn verify_signature(&self, msg: &[u8], sig: &Signature<C>) -> bool {
        let e = generate_challenge::<C>(msg, sig.r.into(), self);

        let lhs = C::GENERATOR * sig.s;
        let rhs = sig.r + (*self) * e;

        lhs == rhs.into_affine()
    }
}

fn generate_challenge<C: BaseConfig>(
    msg: &[u8],
    r: Projective<C>,
    pk: &Affine<C>,
) -> C::ScalarField {
    let mut bytes = Vec::with_capacity(msg.len() + r.compressed_size() + pk.compressed_size());

    bytes.extend_from_slice(msg);
    r.serialize_compressed(&mut bytes)
        .expect("Failed to serialize point");
    pk.serialize_compressed(&mut bytes)
        .expect("Failed to serialize point");

    C::ScalarField::from_be_bytes_mod_order(<C::Hasher as Hasher>::hash(&bytes).as_slice())
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

        let sig = sk.sign(msg);

        let should_valid = pk.verify_signature(msg, &sig);
        let should_invalid = pk.verify_signature(b"wrong message", &sig);

        assert!(should_valid, "Signature should be valid");
        assert!(!should_invalid, "Signature should be invalid");
    }
}
