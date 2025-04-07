use bincode::{config::standard, serde::encode_to_vec, Decode, Encode};
use curv::{
    arithmetic::Converter,
    elliptic::curves::{
        Bls12_381_1, Bls12_381_2, Curve, Ed25519, Point, Ristretto, Scalar, Secp256k1, Secp256r1,
    },
    BigInt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::dkg::{
    classic::{keypair::Keypair, CurveType},
    Data, Scheme,
};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Signature<E: Curve> {
    signature: Option<Scalar<E>>,
    random_pub_key: Option<Point<E>>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Encode, Decode)]
#[derive(Serialize, Deserialize)]
pub struct SignatureBytes {
    curve_type: CurveType,
    signature: Option<Vec<u8>>,
    random_pub_key: Option<Vec<u8>>,
}

impl<E: Curve> Signature<E> {
    pub fn generate<H: Digest + Clone>(seed: &[u8], message: &[u8], keypair: &Keypair<E>) -> Self {
        assert!(!seed.is_empty(), "Seed is empty");
        assert!(!message.is_empty(), "Message is empty");

        let nonce = Self::generate_nonce(seed);
        let random_pub_key = Self::calculate_random_public_key(&nonce);
        let global_pub_key = keypair.public_key();
        let challenge = Self::compute_challenge::<H>(
            message,
            &random_pub_key.to_bytes(true),
            &global_pub_key.to_bytes(true),
        );
        let signature = Self::calculate_signature(challenge.clone(), &nonce, keypair.private_key());

        let signature = Some(signature);
        let random_pub_key = Some(random_pub_key);

        Self {
            signature,
            random_pub_key,
        }
    }

    fn generate_nonce(seed: &[u8]) -> Scalar<E> {
        assert!(!seed.is_empty(), "Seed is empty");

        let b = BigInt::from_bytes(seed);
        Scalar::from_bigint(&b)
    }

    fn calculate_random_public_key(nonce: &Scalar<E>) -> Point<E> {
        Point::generator() * nonce
    }

    fn compute_challenge<H: Digest + Clone>(
        message: &[u8],
        random_public_key_bytes: &[u8],
        global_public_key_bytes: &[u8],
    ) -> Scalar<E> {
        const DOMAIN_SEPARATOR: &[u8] = b"SCHNORR_SIGNATURE";

        let input = [
            DOMAIN_SEPARATOR,
            message,
            random_public_key_bytes,
            global_public_key_bytes,
        ]
        .concat();
        assert!(!message.is_empty(), "Message is empty");

        let hash = H::new().chain(&input).finalize();
        let bigint = BigInt::from_bytes(hash.as_slice());
        Scalar::from_bigint(&bigint)
    }

    fn calculate_signature(
        challenge: Scalar<E>,
        nonce: &Scalar<E>,
        private_key: &Scalar<E>,
    ) -> Scalar<E> {
        nonce - &(challenge * private_key)
    }

    pub fn aggregate<H: Digest + Clone>(
        indices: &[u16],
        signatures: impl IntoIterator<Item = Signature<E>>,
    ) -> Self {
        let signatures: Vec<Signature<E>> = signatures.into_iter().collect();

        assert_eq!(
            indices.len(),
            signatures.len(),
            "Indices and signatures must have the same length"
        );

        assert!(!signatures.is_empty(), "Signatures should not be empty");

        let random_pub_key = signatures[0].random_pub_key.clone();
        assert!(
            signatures
                .iter()
                .all(|sig| sig.random_pub_key == random_pub_key),
            "Random public keys are different"
        );

        let shares = signatures
            .iter()
            .map(|s| s.signature.clone().expect("Missing signature"))
            .collect::<Vec<_>>();

        let sig = lagrange_interpolation(indices, &shares);

        Self {
            signature: Some(sig),
            random_pub_key,
        }
    }

    pub fn validate<H: Digest + Clone>(&self, message: &[u8], public_key: &Point<E>) -> bool {
        let sig = match &self.signature {
            Some(sig) => sig,
            None => return false,
        };

        let r_pub_key = match &self.random_pub_key {
            Some(r_pub_key) => r_pub_key,
            None => return false,
        };

        let challenge = Self::compute_challenge::<H>(
            message,
            &r_pub_key.to_bytes(true),
            &public_key.to_bytes(true),
        );

        let left = Point::generator() * sig;
        let right = r_pub_key - &(public_key * &challenge);

        left == right
    }

    pub fn random_pub_key(&self) -> Option<&Point<E>> {
        self.random_pub_key.as_ref()
    }

    pub fn random() -> Self {
        let signature = Scalar::random();
        let random_pub_key = Point::generator() * &signature;

        let signature = Some(signature);
        let random_pub_key = Some(random_pub_key);

        Self {
            signature,
            random_pub_key,
        }
    }
}

pub fn lagrange_interpolation<E: curv::elliptic::curves::Curve>(
    indices: &[u16],
    shares: &[curv::elliptic::curves::Scalar<E>],
) -> curv::elliptic::curves::Scalar<E> {
    assert_eq!(
        indices.len(),
        shares.len(),
        "Indices and shares must have the same length"
    );

    let points = indices
        .iter()
        .map(|p| (*p).into())
        .collect::<Vec<curv::elliptic::curves::Scalar<E>>>();

    let mut result = curv::elliptic::curves::Scalar::<E>::zero();

    for (i, (xi, yi)) in points.iter().zip(shares.iter()).enumerate() {
        let mut lagrange_coeff = curv::elliptic::curves::Scalar::<E>::from(1);

        for (j, xj) in points.iter().enumerate() {
            if i != j {
                let numerator = curv::elliptic::curves::Scalar::<E>::zero() - xj;
                let denominator = xi.clone() - xj;
                if !denominator.is_zero() {
                    let term = numerator * &denominator.invert().unwrap();
                    lagrange_coeff = lagrange_coeff * &term;
                }
            }
        }

        result = result + (lagrange_coeff * yi);
    }

    result
}

impl SignatureBytes {
    pub fn validate(&self, message: &[u8], key: &[u8]) -> bool {
        match self.curve_type {
            CurveType::Secp256k1 => self.validate_with_established_curve::<Secp256k1>(message, key),
            CurveType::Ed25519 => self.validate_with_established_curve::<Ed25519>(message, key),
            CurveType::Bls12_381_1 => {
                self.validate_with_established_curve::<Bls12_381_1>(message, key)
            }
            CurveType::Bls12_381_2 => {
                self.validate_with_established_curve::<Bls12_381_2>(message, key)
            }
            CurveType::Ristretto => self.validate_with_established_curve::<Ristretto>(message, key),
            CurveType::Secp256r1 => self.validate_with_established_curve::<Secp256r1>(message, key),
            CurveType::Unknown => panic!("Unknown curve type"),
        }
    }

    fn validate_with_established_curve<E: Curve>(&self, message: &[u8], key_bytes: &[u8]) -> bool {
        let r_pub_key_bytes = match &self.random_pub_key {
            Some(r_pub_key) => r_pub_key,
            None => return false,
        };

        let challenge =
            Signature::<E>::compute_challenge::<Sha256>(message, r_pub_key_bytes, key_bytes);

        let sig = match &self.signature {
            Some(sig) => Scalar::<E>::from_bytes(sig),
            None => return false,
        };

        if sig.is_err() {
            return false;
        }
        let sig = sig.unwrap();

        let r_pub_key = match &self.random_pub_key {
            Some(r_pub_key) => Point::<E>::from_bytes(r_pub_key),
            None => return false,
        };
        if r_pub_key.is_err() {
            return false;
        }
        let r_pub_key = r_pub_key.unwrap();

        let public_key = Point::from_bytes(key_bytes);
        if public_key.is_err() {
            return false;
        }
        let public_key = public_key.unwrap();

        let left = Point::generator() * &sig;
        let right = &r_pub_key - &(&public_key * &challenge);

        left == right
    }

    pub fn random() -> Self {
        let curve_type = CurveType::from_type::<Secp256k1>();
        let sig = Signature::<Secp256k1>::random();

        let signature = sig.signature.map(|s| s.to_bytes().to_vec());
        let random_pub_key = sig.random_pub_key.map(|p| p.to_bytes(true).to_vec());

        Self {
            curve_type,
            signature,
            random_pub_key,
        }
    }
}

impl<E: Curve> Scheme for Signature<E> {
    type Error = ();
    type Keypair = Keypair<E>;

    fn sign(seed: &[u8], message: &[u8], keypair: &Self::Keypair) -> Result<Data, Self::Error> {
        let signature = Self::generate::<Sha256>(seed, message, keypair);
        Ok(signature.into())
    }
}

impl<E: Curve> Default for Signature<E> {
    fn default() -> Self {
        let signature = None;
        let random_pub_key = None;

        Self {
            signature,
            random_pub_key,
        }
    }
}

impl<E: Curve> From<Signature<E>> for Vec<u8> {
    fn from(value: Signature<E>) -> Self {
        let bytes = SignatureBytes::from(value);
        let config = standard();

        encode_to_vec(&bytes, config).expect("Failed to encode signature")
    }
}

impl<E: Curve> From<&[u8]> for Signature<E> {
    fn from(value: &[u8]) -> Self {
        let config = standard();
        let (bytes, _): (SignatureBytes, _) =
            bincode::decode_from_slice(value, config).expect("Failed to decode signature");

        bytes.into()
    }
}

impl<E: Curve> From<Signature<E>> for SignatureBytes {
    fn from(value: Signature<E>) -> Self {
        let curve_type = CurveType::from_type::<E>();
        let signature = value.signature.map(|s| s.to_bytes().to_vec());
        let random_pub_key = value.random_pub_key.map(|p| p.to_bytes(true).to_vec());

        Self {
            curve_type,
            signature,
            random_pub_key,
        }
    }
}

impl<E: Curve> From<SignatureBytes> for Signature<E> {
    fn from(value: SignatureBytes) -> Self {
        let signature = value.signature.map(|s| Scalar::from_bytes(&s).unwrap());
        let random_pub_key = value.random_pub_key.map(|p| Point::from_bytes(&p).unwrap());

        Self {
            signature,
            random_pub_key,
        }
    }
}

impl<E: Curve> From<Signature<E>> for Data {
    fn from(value: Signature<E>) -> Self {
        Data::Classic(SignatureBytes::from(value))
    }
}

impl<E: Curve> From<Data> for Signature<E> {
    fn from(value: Data) -> Self {
        match value {
            Data::Classic(bytes) => Signature::from(bytes),
        }
    }
}

#[cfg(test)]
mod signature_tests {
    use curv::elliptic::curves::Secp256k1;
    use sha2::Sha256;

    use crate::crypto::dkg::classic::{keypair::Keypair, Signature};

    type E = Secp256k1;
    type H = Sha256;

    const SEED: &[u8] = b"test_seed";
    const MESSAGE: &[u8] = b"test_message";
    const DIFFERENT_MESSAGE: &[u8] = b"different_message";
    const ANOTHER_SEED: &[u8] = b"another_seed";

    #[test]
    fn signature_validates_with_correct_message_and_key() {
        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert!(signature.validate::<H>(MESSAGE, keypair.public_key()));
    }

    #[test]
    fn signature_fails_with_different_message() {
        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert!(!signature.validate::<H>(DIFFERENT_MESSAGE, keypair.public_key()));
    }

    #[test]
    fn signature_fails_with_different_public_key() {
        let keypair = Keypair::<E>::random();
        let different_keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert!(!signature.validate::<H>(MESSAGE, different_keypair.public_key()));
    }

    #[test]
    fn default_signature_is_invalid() {
        let keypair = Keypair::<E>::random();
        let default_signature = Signature::<E>::default();

        assert!(!default_signature.validate::<H>(MESSAGE, keypair.public_key()));
    }

    #[test]
    fn signatures_with_same_input_are_identical() {
        let keypair = Keypair::<E>::random();
        let signature1 = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);
        let signature2 = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert_eq!(signature1.signature, signature2.signature);
        assert_eq!(signature1.random_pub_key, signature2.random_pub_key);
    }

    #[test]
    fn signatures_with_different_seeds_are_different() {
        let keypair = Keypair::<E>::random();
        let signature1 = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);
        let signature2 = Signature::<E>::generate::<H>(ANOTHER_SEED, MESSAGE, &keypair);

        assert_ne!(signature1.signature, signature2.signature);
        assert_ne!(signature1.random_pub_key, signature2.random_pub_key);
    }

    #[test]
    fn serialization_deserialization_preserves_signature() {
        let keypair = Keypair::<E>::random();
        let original = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        let serialized: Vec<u8> = original.clone().into();
        let deserialized = Signature::<E>::from(serialized.as_slice());

        assert_eq!(original, deserialized);
        assert!(deserialized.validate::<H>(MESSAGE, keypair.public_key()));
    }

    #[test]
    fn aggregated_signature_validates_correctly() {
        const NUM_SIGNERS: u16 = 3;

        let keypairs = Keypair::<E>::related_random::<H, _>(NUM_SIGNERS, |n| 2 * n / 3);

        let indices: Vec<u16> = (1..NUM_SIGNERS + 1).collect();

        let signatures = keypairs
            .iter()
            .map(|keypair| Signature::<E>::generate::<H>(SEED, MESSAGE, keypair))
            .collect::<Vec<_>>();

        assert_eq!(
            indices.len(),
            signatures.len(),
            "Indices and signatures must have the same length"
        );

        let aggregated = Signature::<E>::aggregate::<H>(&indices, signatures);

        let is_valid = aggregated.validate::<H>(MESSAGE, keypairs[0].public_key());

        assert!(is_valid, "Aggregated signature should be valid");
    }

    #[test]
    #[should_panic(expected = "Seed is empty")]
    fn empty_seed_causes_panic() {
        let keypair = Keypair::<E>::random();
        let _signature = Signature::<E>::generate::<H>(&[], MESSAGE, &keypair);
    }

    #[test]
    #[should_panic(expected = "Message is empty")]
    fn empty_message_causes_panic() {
        let keypair = Keypair::<E>::random();
        let _signature = Signature::<E>::generate::<H>(SEED, &[], &keypair);
    }

    #[test]
    #[should_panic(expected = "Signatures should not be empty")]
    fn aggregate_empty_signatures_causes_panic() {
        let signatures: Vec<Signature<E>> = vec![];
        let _aggregated = Signature::<E>::aggregate::<H>(&[], signatures);
    }

    #[test]
    #[should_panic(expected = "Indices and signatures must have the same length")]
    fn aggregate_mismatched_indices_causes_panic() {
        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);
        let signatures = vec![signature];
        let indices = [1, 2];

        let _aggregated = Signature::<E>::aggregate::<H>(&indices, signatures);
    }

    #[test]
    fn random_pub_key_returns_correct_value() {
        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert!(signature.random_pub_key().is_some());

        let default_signature = Signature::<E>::default();
        assert!(default_signature.random_pub_key().is_none());
    }
}
