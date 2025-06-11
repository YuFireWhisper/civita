use ark_ec::{short_weierstrass::Affine, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::crypto::{
    self,
    ec::{
        hash_to_curve::{self, HashToCurve},
        secret_key::SecretKey,
        serialize_size::SerializeSize,
    },
    traits::{
        self,
        hasher::{Hasher, Output},
        vrf::{Prover, VerifyProof},
    },
};

mod challenge_generator;
mod nonce_generator;
mod suites;

#[derive(Debug)]
pub struct Proof<C: Config> {
    pub gamma: Affine<C>,
    pub c: C::ScalarField,
    pub s: C::ScalarField,
}

pub trait Config: hash_to_curve::Config + SerializeSize {
    const COFACTOR_SCALAR: Self::ScalarField;
}

impl<C: Config> traits::vrf::Proof<C::Hasher> for Proof<C> {
    fn proof_to_hash(&self) -> Output<<C::Hasher as Hasher>::OutputSizeInBytes> {
        const DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
        const DOMAIN_SEPARATOR_BACK: u8 = 0x00;

        let mut bytes = Vec::new();
        bytes.push(DOMAIN_SEPARATOR_FRONT);
        bytes.extend_from_slice((self.gamma * C::COFACTOR_SCALAR).to_string().as_bytes());
        bytes.push(DOMAIN_SEPARATOR_BACK);

        C::Hasher::hash(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::Error> {
        if bytes.len() != C::AFFINE_SIZE + C::SCALAR_SIZE * 2 {
            return Err(crypto::Error::Serialization(
                "Invalid proof size".to_string(),
            ));
        }

        let gamma = Affine::<C>::deserialize_compressed(&bytes[..C::AFFINE_SIZE])
            .map_err(crypto::Error::from)?;
        let c = C::ScalarField::from_be_bytes_mod_order(
            &bytes[C::AFFINE_SIZE..C::AFFINE_SIZE + C::SCALAR_SIZE],
        );
        let s = C::ScalarField::from_be_bytes_mod_order(&bytes[C::AFFINE_SIZE + C::SCALAR_SIZE..]);

        Ok(Proof { gamma, c, s })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(C::AFFINE_SIZE + C::SCALAR_SIZE * 2);
        self.gamma
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize gamma");
        self.c
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize challenge");
        self.s
            .serialize_compressed(&mut bytes)
            .expect("Failed to serialize response");
        bytes
    }
}

impl<C: Config> Prover<Proof<C>, C::Hasher> for SecretKey<C> {
    fn prove(&self, alpha: &[u8]) -> Proof<C> {
        let y = (C::GENERATOR * self.sk).into_affine();
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

impl<C: Config> VerifyProof<Proof<C>, C::Hasher> for Affine<C> {
    fn verify_proof(&self, alpha: &[u8], proof: &Proof<C>) -> bool {
        let h = C::hash_to_curve(alpha);
        let u = C::GENERATOR * proof.s - (*self) * proof.c;
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

    use crate::crypto::traits::vrf::{Prover, VerifyProof};

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

        assert!(is_valid);
        assert!(!should_invalid);
    }
}
