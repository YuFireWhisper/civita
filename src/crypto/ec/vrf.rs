use ark_ec::{short_weierstrass::Affine, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

use crate::crypto::{
    self,
    ec::{
        hash_to_curve::{self, HashToCurve},
        secret_key::SecretKey,
    },
    traits::{
        self,
        hasher::{HashArray, Hasher},
        vrf::{Prover, VerifyProof},
        SecretKey as _,
    },
};

mod challenge_generator;
mod nonce_generator;
mod suites;

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derivative(Debug(bound = ""))]
#[derivative(Eq(bound = ""), PartialEq(bound = ""))]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<C: Config> {
    pub gamma: Affine<C>,
    pub c: C::ScalarField,
    pub s: C::ScalarField,
}

pub trait Config: hash_to_curve::Config {
    const COFACTOR_SCALAR: Self::ScalarField;
}

impl<C: Config> traits::vrf::Proof for Proof<C> {
    type Hasher = C::Hasher;

    fn proof_to_hash(&self) -> HashArray<Self::Hasher> {
        const DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
        const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        let mut bytes = Vec::new();
        bytes.push(DOMAIN_SEPARATOR_FRONT);
        bytes.extend_from_slice((self.gamma * C::COFACTOR_SCALAR).to_string().as_bytes());
        bytes.push(DOMAIN_SEPARATOR_BACK);

        C::Hasher::hash(&bytes)
    }

    fn from_slice(bytes: &[u8]) -> Result<Self, crypto::Error> {
        Self::deserialize_compressed(bytes).map_err(crypto::Error::from)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.compressed_size());
        self.serialize_compressed(&mut bytes)
            .expect("Failed to serialize VRF proof");
        bytes
    }
}

impl<C: Config> Prover for SecretKey<C> {
    type Proof = Proof<C>;

    fn prove(&self, alpha: &[u8]) -> Proof<C> {
        let y = self.public_key();
        let h = C::hash_to_curve(alpha);
        let gamma = (h * self.sk).into_affine();
        let k = nonce_generator::generate_nonce::<C::Hasher, C::ScalarField>(self.sk, alpha);

        let c = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>([
            y,
            h,
            gamma,
            (C::GENERATOR * k).into(),
            (h * k).into(),
        ]);

        let s = k + c * self.sk;

        Proof { gamma, c, s }
    }
}

impl<C: Config> VerifyProof for Affine<C> {
    type Proof = Proof<C>;

    fn verify_proof(&self, alpha: &[u8], proof: &Self::Proof) -> bool {
        let h = C::hash_to_curve(alpha);
        let u = C::GENERATOR * proof.s - *self * proof.c;
        let v = h * proof.s - proof.gamma * proof.c;
        let c_prime = challenge_generator::generate_challenge::<Affine<C>, C::Hasher>([
            *self,
            h,
            proof.gamma,
            u.into(),
            v.into(),
        ]);

        proof.c == c_prime
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::MontFp;
    use ark_secp256r1::{Affine, Fq, Fr};

    use crate::crypto::traits::vrf::{Proof, Prover, VerifyProof};

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
        use crate::crypto::ec::secret_key::SecretKey;

        let pk = Affine::new(PK_X, PK_Y);

        let sk = SecretKey::new(SK);
        let proof = sk.prove(alpha.as_bytes());

        let is_valid = pk.verify_proof(alpha.as_bytes(), &proof);
        let should_invalid = pk.verify_proof(b"invalid", &proof);

        let deserialized = super::Proof::<ark_secp256r1::Config>::from_slice(&proof.to_bytes());

        assert!(is_valid);
        assert!(!should_invalid);
        assert_eq!(proof, deserialized.unwrap());
    }
}
