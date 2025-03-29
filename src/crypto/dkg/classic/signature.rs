use bincode::{config::standard, serde::encode_to_vec, Decode, Encode};
use curv::{
    arithmetic::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::crypto::dkg::classic::keypair::{to_scalars, Keypair, PrivateKey, PublicKey};

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Signature<E: Curve> {
    signature: Option<Scalar<E>>,
    random_pub_key: Option<PublicKey<E>>,
    challenge: Option<Scalar<E>>,
    global_pub_key: Option<PublicKey<E>>,
}

#[derive(Serialize, Deserialize, Encode, Decode)]
struct SignatureBytes {
    signature: Option<Vec<u8>>,
    random_pub_key: Option<Vec<u8>>,
    challenge: Option<Vec<u8>>,
    global_pub_key: Option<Vec<u8>>,
}

impl<E: Curve> Signature<E> {
    pub fn generate<H: Digest + Clone>(seed: &[u8], message: &[u8], keypair: &Keypair<E>) -> Self {
        let nonce = Self::generate_nonce(seed);
        let random_pub_key = Self::calculate_random_public_key(&nonce);
        let global_pub_key = keypair.public_key();
        let challenge = Self::compute_challenge::<H>(
            message,
            &random_pub_key.to_bytes(),
            &global_pub_key.to_bytes(),
        );
        let signature = Self::calculate_signature(challenge.clone(), &nonce, keypair.private_key());

        let signature = Some(signature);
        let random_pub_key = Some(random_pub_key);
        let challenge = Some(challenge);
        let global_pub_key = Some(global_pub_key.clone());

        Self {
            signature,
            random_pub_key,
            challenge,
            global_pub_key,
        }
    }

    fn generate_nonce(seed: &[u8]) -> Scalar<E> {
        assert!(!seed.is_empty(), "Seed is empty");

        let b = BigInt::from_bytes(seed);
        Scalar::from_bigint(&b)
    }

    fn calculate_random_public_key(nonce: &Scalar<E>) -> PublicKey<E> {
        (Point::generator() * nonce).into()
    }

    fn compute_challenge<H: Digest + Clone>(
        message: &[u8],
        random_public_key_bytes: &[u8],
        global_public_key_bytes: &[u8],
    ) -> Scalar<E> {
        assert!(!message.is_empty(), "Message is empty");

        let input = [message, random_public_key_bytes, global_public_key_bytes].concat();
        let hash = H::new().chain(&input).finalize();
        let bigint = BigInt::from_bytes(hash.as_slice());

        Scalar::from_bigint(&bigint)
    }

    fn calculate_signature(
        challenge: Scalar<E>,
        nonce: &Scalar<E>,
        private_key: &PrivateKey<E>,
    ) -> Scalar<E> {
        nonce + &(challenge * private_key)
    }

    pub fn aggregate<H: Digest + Clone>(
        indices: &[u16],
        signatures: impl IntoIterator<Item = Signature<E>>,
    ) -> Self {
        let mut signatures: Vec<Signature<E>> = signatures.into_iter().collect();

        assert_eq!(
            indices.len(),
            signatures.len(),
            "Indices and signatures must have the same length"
        );

        assert!(
            Self::check_all_equal(&signatures), 
            "Items in signatures are not equal"
        );

        let first_sig = signatures.pop().expect("Signatures are empty");
        let random_pub_key = first_sig.random_pub_key;
        let global_pub_key = first_sig.global_pub_key;
        let challenge = first_sig.challenge;

        let points = to_scalars(indices);
        let value = signatures
            .into_iter()
            .map(|s| s.signature.expect("Missing signature"))
            .chain(std::iter::once(
                first_sig.signature.expect("Missing signature"),
            ))
            .collect::<Vec<_>>();
        let sig = VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &value);

        Self {
            signature: Some(sig),
            random_pub_key,
            challenge,
            global_pub_key,
        }
    }

    fn check_all_equal(signatures: &[Signature<E>]) -> bool {
        let random_pub_key = &signatures
            .first()
            .expect("Signatures are empty")
            .random_pub_key;
        let global_pub_key = &signatures
            .first()
            .expect("Signatures are empty")
            .global_pub_key;
        let challenge = &signatures.first().expect("Signatures are empty").challenge;

        if random_pub_key.is_none() || global_pub_key.is_none() || challenge.is_none() {
            return false;
        }

        let random_pub_key_eq = signatures.iter().all(|s| {
            s.random_pub_key == *random_pub_key
        });

        assert!(random_pub_key_eq, "Random public keys are different");

        let global_pub_key_eq = signatures.iter().all(|s| {
            s.global_pub_key == *global_pub_key
        });

        assert!(global_pub_key_eq, "Global public keys are different");

        let challenge_eq = signatures.iter().all(|s| {
            s.challenge == *challenge
        });

        assert!(challenge_eq, "Challenges are different");

        random_pub_key_eq && global_pub_key_eq && challenge_eq
    }

    pub fn validate(&self) -> bool {
        let sig = match &self.signature {
            Some(sig) => sig,
            None => return false,
        };
        let challenge = match &self.challenge {
            Some(challenge) => challenge,
            None => return false,
        };
        let r_pub_key = match &self.random_pub_key {
            Some(r_pub_key) => r_pub_key,
            None => return false,
        };
        let pub_key = match &self.global_pub_key {
            Some(pub_key) => pub_key,
            None => return false,
        };

        Point::generator() * sig == r_pub_key + &(pub_key * challenge)
    }

    pub fn random_pub_key(&self) -> Option<&PublicKey<E>> {
        self.random_pub_key.as_ref()
    }
}

impl<E: Curve> Default for Signature<E> {
    fn default() -> Self {
        let signature = None;
        let random_pub_key = None;
        let challenge = None;
        let global_pub_key = None;

        Self {
            signature,
            random_pub_key,
            challenge,
            global_pub_key,
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
        let signature = value.signature.map(|s| s.to_bytes().to_vec());
        let random_pub_key = value.random_pub_key.map(|p| p.to_bytes());
        let challenge = value.challenge.map(|c| c.to_bytes().to_vec());
        let global_pub_key = value.global_pub_key.map(|p| p.to_bytes());

        Self {
            signature,
            random_pub_key,
            challenge,
            global_pub_key,
        }
    }
}

impl<E: Curve> From<SignatureBytes> for Signature<E> {
    fn from(value: SignatureBytes) -> Self {
        let signature = value
            .signature
            .map(|s| Scalar::from_bytes(&s).expect("Invalid scalar"));
        let random_pub_key = value.random_pub_key.map(|p| PublicKey::from_bytes(&p));
        let challenge = value
            .challenge
            .map(|c| Scalar::from_bytes(&c).expect("Invalid scalar"));
        let global_pub_key = value.global_pub_key.map(|p| PublicKey::from_bytes(&p));

        Self {
            signature,
            random_pub_key,
            challenge,
            global_pub_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    use sha2::Sha256;

    use crate::crypto::dkg::classic::{
        keypair::{Keypair, PublicKey},
        Signature,
    };

    type E = Secp256k1;
    type H = Sha256;

    #[test]
    fn generate_signature_validates_correctly() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        assert!(signature.validate());
    }

    #[test]
    fn different_seeds_produce_different_signatures() {
        const SEED1: &[u8] = b"test_seed_1";
        const SEED2: &[u8] = b"test_seed_2";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        let signature1 = Signature::<E>::generate::<H>(SEED1, MESSAGE, &keypair);
        let signature2 = Signature::<E>::generate::<H>(SEED2, MESSAGE, &keypair);

        assert_ne!(signature1.signature, signature2.signature);
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE1: &[u8] = b"test_message_1";
        const MESSAGE2: &[u8] = b"test_message_2";

        let keypair = Keypair::<E>::random();
        let signature1 = Signature::<E>::generate::<H>(SEED, MESSAGE1, &keypair);
        let signature2 = Signature::<E>::generate::<H>(SEED, MESSAGE2, &keypair);

        assert_ne!(signature1.signature, signature2.signature);
    }

    #[test]
    fn different_keypairs_produce_different_signatures() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE: &[u8] = b"test_message";

        let keypair1 = Keypair::<E>::random();
        let keypair2 = Keypair::<E>::random();
        let signature1 = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair1);
        let signature2 = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair2);

        assert_ne!(signature1.signature, signature2.signature);
    }

    #[test]
    #[should_panic(expected = "Seed is empty")]
    fn empty_seed_should_panic() {
        const EMPTY_SEED: &[u8] = b"";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        Signature::<E>::generate::<H>(EMPTY_SEED, MESSAGE, &keypair);
    }

    #[test]
    #[should_panic(expected = "Message is empty")]
    fn empty_message_should_panic() {
        const SEED: &[u8] = b"test_seed";
        const EMPTY_MESSAGE: &[u8] = b"";

        let keypair = Keypair::<E>::random();
        Signature::<E>::generate::<H>(SEED, EMPTY_MESSAGE, &keypair);
    }

    #[test]
    fn serialize_deserialize_signature() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        let serialized: Vec<u8> = signature.clone().into();
        let deserialized = Signature::<E>::from(serialized.as_slice());

        assert_eq!(signature, deserialized);
    }

    #[test]
    fn default_signature_is_invalid() {
        let signature = Signature::<E>::default();

        assert!(!signature.validate());
    }

    #[test]
    fn aggregate_signatures_from_single_signer() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        let indices = vec![1];
        let signatures = vec![signature.clone()];

        let aggregated = Signature::<E>::aggregate::<H>(&indices, signatures);

        assert_eq!(signature, aggregated);
        assert!(aggregated.validate());
    }

    #[test]
    fn aggregate_signatures_from_multiple_signers() {
        let keypair1 = Keypair::<E>::random();

        let global_public_key = keypair1.public_key();

        let random_scalar = Scalar::<E>::random();
        let random_point = Point::<E>::generator() * &random_scalar;
        let random_public_key: PublicKey<E> = random_point.into();

        let challenge = Scalar::<E>::random();

        let sig1 = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: Some(random_public_key.clone()),
            challenge: Some(challenge.clone()),
            global_pub_key: Some(global_public_key.clone()),
        };

        let sig2 = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: Some(random_public_key.clone()),
            challenge: Some(challenge.clone()),
            global_pub_key: Some(global_public_key.clone()),
        };

        let sig3 = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: Some(random_public_key.clone()),
            challenge: Some(challenge.clone()),
            global_pub_key: Some(global_public_key.clone()),
        };

        let indices = vec![1, 2, 3];
        let signatures = vec![sig1, sig2, sig3];

        let aggregated = Signature::<E>::aggregate::<H>(&indices, signatures);

        assert!(aggregated.random_pub_key.is_some());
        assert!(aggregated.challenge.is_some());
        assert!(aggregated.global_pub_key.is_some());
        assert!(aggregated.signature.is_some());
    }

    #[test]
    #[should_panic(expected = "Indices and signatures must have the same length")]
    fn aggregate_signatures_with_mismatched_indices_should_panic() {
        const SEED: &[u8] = b"test_seed";
        const MESSAGE: &[u8] = b"test_message";

        let keypair = Keypair::<E>::random();
        let signature = Signature::<E>::generate::<H>(SEED, MESSAGE, &keypair);

        let indices = vec![1, 2];
        let signatures = vec![signature];

        Signature::<E>::aggregate::<H>(&indices, signatures);
    }

    #[test]
    #[should_panic(expected = "Signatures are empty")]
    fn aggregate_empty_signatures_should_panic() {
        let indices: Vec<u16> = vec![];
        let signatures: Vec<Signature<E>> = vec![];

        Signature::<E>::aggregate::<H>(&indices, signatures);
    }

    #[test]
    #[should_panic(expected = "Random public keys are different")]
    fn aggregate_different_random_pub_keys_should_panic() {
        let keypair1 = Keypair::<E>::random();
        let keypair2 = Keypair::<E>::random();

        let sig1 = Signature::<E>::generate::<H>(b"seed1", b"message", &keypair1);
        let sig2 = Signature::<E>::generate::<H>(b"seed2", b"message", &keypair2);

        let indices = vec![1, 2];
        let signatures = vec![sig1, sig2];

        Signature::<E>::aggregate::<H>(&indices, signatures);
    }

    #[test]
    fn validate_returns_false_for_missing_signature() {
        let signature = Signature::<E> {
            signature: None,
            random_pub_key: Some(Keypair::<E>::random().public_key().clone()),
            challenge: Some(Scalar::<E>::random()),
            global_pub_key: Some(Keypair::<E>::random().public_key().clone()),
        };

        assert!(!signature.validate());
    }

    #[test]
    fn validate_returns_false_for_missing_challenge() {
        let signature = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: Some(Keypair::<E>::random().public_key().clone()),
            challenge: None,
            global_pub_key: Some(Keypair::<E>::random().public_key().clone()),
        };

        assert!(!signature.validate());
    }

    #[test]
    fn validate_returns_false_for_missing_random_pub_key() {
        let signature = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: None,
            challenge: Some(Scalar::<E>::random()),
            global_pub_key: Some(Keypair::<E>::random().public_key().clone()),
        };

        assert!(!signature.validate());
    }

    #[test]
    fn validate_returns_false_for_missing_global_pub_key() {
        let signature = Signature::<E> {
            signature: Some(Scalar::<E>::random()),
            random_pub_key: Some(Keypair::<E>::random().public_key().clone()),
            challenge: Some(Scalar::<E>::random()),
            global_pub_key: None,
        };

        assert!(!signature.validate());
    }
}
