use ark_ec::{
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{ec::serialize_affine, traits::hasher::Hasher};

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Signature<C: SWCurveConfig> {
    #[serde(with = "serialize_affine")]
    pub r: Affine<C>,
    pub s: C::ScalarField,
}

pub fn sign<C: SWCurveConfig, H: Hasher>(
    sk: C::ScalarField,
    pk: Affine<C>,
    msg: &[u8],
) -> Signature<C> {
    let mut random = [0u8; 32];
    rand::rng().fill(&mut random);

    let k = C::ScalarField::from_be_bytes_mod_order(&random);
    let r = C::GENERATOR * k;
    let e = generate_challenge::<C, H>(msg, r, pk);
    let s = k + e * sk;

    Signature {
        r: r.into_affine(),
        s,
    }
}

fn generate_challenge<C: SWCurveConfig, H: Hasher>(
    msg: &[u8],
    r: Projective<C>,
    pk: Affine<C>,
) -> C::ScalarField {
    let mut bytes = Vec::with_capacity(msg.len() + r.compressed_size() + pk.compressed_size());

    bytes.extend_from_slice(msg);
    r.serialize_compressed(&mut bytes)
        .expect("Failed to serialize point");
    pk.serialize_compressed(&mut bytes)
        .expect("Failed to serialize point");

    C::ScalarField::from_be_bytes_mod_order(&H::hash(&bytes))
}

pub fn verify<C: SWCurveConfig, H: Hasher>(sig: &Signature<C>, pk: Affine<C>, msg: &[u8]) -> bool {
    let e = generate_challenge::<C, H>(msg, sig.r.into(), pk);

    let lhs = C::GENERATOR * sig.s;
    let rhs = sig.r + pk * e;

    lhs == rhs.into_affine()
}

#[cfg(test)]
mod tests {
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
        let pk = Affine::new(PK_X, PK_Y);

        let sig = sign::<ark_secp256r1::Config, sha2::Sha256>(SK, pk, msg);

        assert!(verify::<ark_secp256r1::Config, sha2::Sha256>(&sig, pk, msg));
        assert!(!verify::<ark_secp256r1::Config, sha2::Sha256>(
            &sig,
            pk,
            b"wrong message"
        ));
    }
}
