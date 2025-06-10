use ark_ec::{short_weierstrass::Affine, CurveGroup};
use serde::{Deserialize, Serialize};

use crate::crypto::{
    self,
    ec::{
        hash_to_curve::{self, HashToCurve},
        public_key::PublicKey,
        secret_key::SecretKey,
        serialize_affine,
    },
    traits::{
        self,
        hasher::Hasher,
        vrf::{Prove, VerifyProof},
    },
};

mod challenge_generator;
mod nonce_generator;
mod suites;

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Proof<C: Config> {
    #[serde(with = "serialize_affine")]
    pub gamma: Affine<C>,
    pub c: C::ScalarField,
    pub s: C::ScalarField,
}

pub trait Config: hash_to_curve::Config {
    const COFACTOR_SCALAR: Self::ScalarField;
}

impl<C: Config> traits::vrf::Proof for Proof<C> {
    fn proof_to_hash(&self) -> Vec<u8> {
        proof_to_hash::<C>(self)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::Error> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard())
            .map(|(proof, _)| proof)
            .map_err(crypto::Error::from)
    }

    fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .expect("Serialization should not fail")
    }
}

impl<C: Config> Prove<Proof<C>> for SecretKey<C> {
    fn prove(&self, alpha: &[u8]) -> Proof<C> {
        prove::<C>(self.sk, alpha)
    }
}

impl<C: Config> VerifyProof<Proof<C>> for PublicKey<C> {
    fn verify_proof(self, alpha: &[u8], proof: &Proof<C>) -> bool {
        verify::<C>(self, alpha, proof)
    }
}

fn prove<C: Config>(sk: C::ScalarField, alpha: &[u8]) -> Proof<C> {
    let y = (C::GENERATOR * sk).into_affine();
    let h = C::hash_to_curve(alpha);
    let gamma = (h * sk).into_affine();
    let k = nonce_generator::generate_nonce::<C::Hasher, C::ScalarField>(sk, alpha);

    let c = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>([
        y,
        h,
        gamma,
        (C::GENERATOR * k).into(),
        (h * k).into(),
    ]);

    let s = k + c * sk;

    Proof { gamma, c, s }
}

fn verify<C: Config>(pk: Affine<C>, alpha: &[u8], proof: &Proof<C>) -> bool {
    let h = C::hash_to_curve(alpha);
    let u = C::GENERATOR * proof.s - pk * proof.c;
    let v = h * proof.s - proof.gamma * proof.c;
    let c_prime = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>([
        pk,
        h,
        proof.gamma,
        u.into(),
        v.into(),
    ]);

    proof.c == c_prime
}

fn proof_to_hash<C: Config>(proof: &Proof<C>) -> Vec<u8> {
    const DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
    const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

    let mut bytes = Vec::new();
    bytes.push(DOMAIN_SEPARATOR_FRONT);
    bytes.extend_from_slice((proof.gamma * C::COFACTOR_SCALAR).to_string().as_bytes());
    bytes.push(DOMAIN_SEPARATOR_BACK);

    C::Hasher::hash(&bytes)
}

#[cfg(test)]
mod tests {
    use ark_ff::MontFp;
    use ark_secp256r1::{Affine, Fq, Fr};

    const SK: Fr =
        MontFp!("91225253027397101270059260515990221874496108017261222445699397644687913215777");
    const PK_X: Fq = MontFp!("0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    const PK_Y: Fq = MontFp!("0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");

    #[rstest::rstest]
    #[case("sample")]
    #[case("abc")]
    #[case("abcdef0123456789")]
    #[test]
    fn corrent_value(#[case] alpha: &str) {
        use crate::crypto::ec::vrf::{prove, verify};

        let pk = Affine::new(PK_X, PK_Y);

        let proof = prove::<ark_secp256r1::Config>(SK, alpha.as_bytes());

        assert!(verify::<ark_secp256r1::Config>(
            pk,
            alpha.as_bytes(),
            &proof
        ));
    }
}
