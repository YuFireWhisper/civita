use bincode::{config::standard, serde::encode_to_vec, Decode, Encode};
use curv::{
    arithmetic::Converter,
    cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS,
    elliptic::curves::{Curve, Point, Scalar},
    BigInt,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Serialize, Deserialize, Encode, Decode)]
struct SignatureBytes {
    sig: Option<Vec<u8>>,
    r_pub_key: Option<Vec<u8>>,
    challenge: Option<Vec<u8>>,
    index: Option<u16>,
    g_pub_key: Option<Vec<u8>>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Serialize, Deserialize)]
#[derive(PartialEq, Eq)]
pub struct Signature<E: Curve> {
    sig: Option<Scalar<E>>,
    r_pub_key: Option<Point<E>>,
    challenge: Option<Scalar<E>>,
    index: Option<u16>,
    secret: Option<Scalar<E>>,
    g_pub_key: Option<Point<E>>,
}

impl<E: Curve> Default for Signature<E> {
    fn default() -> Self {
        let sig = None;
        let r_pub_key = None;
        let challenge = None;
        let index = None;
        let g_pub_key = None;
        let secret = None;

        Self {
            sig,
            r_pub_key,
            challenge,
            index,
            secret,
            g_pub_key,
        }
    }
}

impl<E: Curve> Signature<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_keypair(mut self, secret: Scalar<E>, global_public_key: Point<E>) -> Self {
        self.secret = Some(secret);
        self.g_pub_key = Some(global_public_key);
        self
    }

    pub fn with_global_public_key(mut self, global_public_key: Point<E>) -> Self {
        self.g_pub_key = Some(global_public_key);
        self
    }

    pub fn generate<H: Digest + Clone>(mut self, seed: &[u8], message: &[u8]) -> Self {
        let nonce = Self::generate_nonce(seed);
        let r_pub_key = Self::calculate_random_public_key(&nonce);
        self.r_pub_key = Some(r_pub_key);
        let challenge = self.compute_challenge::<H>(message);
        self.challenge = Some(challenge);
        let sig = self.calculate_signature(&nonce);

        self.sig = Some(sig);
        self
    }

    fn generate_nonce(seed: &[u8]) -> Scalar<E> {
        assert!(!seed.is_empty(), "Seed is empty");

        let b = BigInt::from_bytes(seed);
        Scalar::from_bigint(&b)
    }

    fn calculate_random_public_key(k: &Scalar<E>) -> Point<E> {
        Point::generator() * k
    }

    fn compute_challenge<H: Digest + Clone>(&self, message: &[u8]) -> Scalar<E> {
        assert!(!message.is_empty(), "Message is empty");

        let r_pub_key = self
            .random_public_key_bytes()
            .expect("Random public key is missing");
        let g_pub_key = self
            .global_public_key_bytes()
            .expect("Global public key is missing");

        let input = [message, &r_pub_key, &g_pub_key].concat();
        let hash = H::new().chain(&input).finalize();
        let bigint = BigInt::from_bytes(hash.as_slice());

        Scalar::from_bigint(&bigint)
    }

    pub fn random_public_key_bytes(&self) -> Option<Vec<u8>> {
        self.r_pub_key
            .as_ref()
            .map(|point| point.to_bytes(true).to_vec())
    }

    fn global_public_key_bytes(&self) -> Option<Vec<u8>> {
        self.g_pub_key
            .as_ref()
            .map(|point| point.to_bytes(true).to_vec())
    }

    fn calculate_signature(&self, nonce: &Scalar<E>) -> Scalar<E> {
        let challenge = self.challenge().expect("Challenge is missing");
        let secret = self.secret().expect("Secret is missing");
        nonce + &(challenge * secret)
    }

    fn secret(&self) -> Option<&Scalar<E>> {
        self.secret.as_ref()
    }

    pub fn with_signature(mut self, signature: Scalar<E>) -> Self {
        self.sig = Some(signature);
        self
    }

    pub fn with_random_public_key(mut self, random_public_key: Point<E>) -> Self {
        self.r_pub_key = Some(random_public_key);
        self
    }

    pub fn signature(&self) -> Option<&Scalar<E>> {
        self.sig.as_ref()
    }

    pub fn random_public_key(&self) -> Option<&Point<E>> {
        self.r_pub_key.as_ref()
    }

    pub fn aggregate<H: Digest + Clone>(&self, others: &[Self]) -> Self {
        let r_pub_key = self
            .random_public_key()
            .expect("Random public key is missing");
        let g_pub_key = self
            .global_public_key()
            .expect("Global public key is missing");

        let mut points: Vec<Scalar<E>> = Vec::new();
        let mut scalars: Vec<Scalar<E>> = Vec::new();

        points.push(self.index().expect("Index is missing").into());
        scalars.push(self.signature().expect("Signature is missing").clone());

        for sig in others {
            assert_eq!(
                sig.random_public_key(),
                Some(r_pub_key),
                "Random public keys are different"
            );
            assert_eq!(
                sig.global_public_key_bytes(),
                self.global_public_key_bytes(),
                "Global public keys are different"
            );

            points.push(sig.index().expect("Index is missing").into());
            scalars.push(sig.signature().expect("Signature is missing").clone());
        }

        let sig = VerifiableSS::<E, H>::lagrange_interpolation_at_zero(&points, &scalars);

        Self::new()
            .with_signature(sig)
            .with_random_public_key(r_pub_key.clone())
            .with_global_public_key(g_pub_key.clone())
    }

    fn global_public_key(&self) -> Option<&Point<E>> {
        self.g_pub_key.as_ref()
    }

    fn index(&self) -> Option<u16> {
        self.index
    }

    pub fn set_index(&mut self, index: u16) {
        self.index = Some(index);
    }

    pub fn validate(&self) -> bool {
        let sig = match self.signature() {
            Some(sig) => sig,
            None => return false,
        };
        let challenge = match self.challenge() {
            Some(challenge) => challenge,
            None => return false,
        };
        let r_pub_key = match self.random_public_key() {
            Some(r_pub_key) => r_pub_key,
            None => return false,
        };
        let g_pub_key = match self.global_public_key() {
            Some(g_pub_key) => g_pub_key,
            None => return false,
        };

        Point::generator() * sig == r_pub_key + &(g_pub_key * challenge)
    }

    fn challenge(&self) -> Option<&Scalar<E>> {
        self.challenge.as_ref()
    }
}

impl<E: Curve> From<Signature<E>> for SignatureBytes {
    fn from(value: Signature<E>) -> Self {
        let sig = value.sig.map(|s| s.to_bytes().to_vec());
        let r_pub_key = value.r_pub_key.map(|p| p.to_bytes(true).to_vec());
        let challenge = value.challenge.map(|c| c.to_bytes().to_vec());
        let index = value.index;
        let g_pub_key = value.g_pub_key.map(|p| p.to_bytes(true).to_vec());

        Self {
            sig,
            r_pub_key,
            challenge,
            index,
            g_pub_key,
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

impl<E: Curve> From<SignatureBytes> for Signature<E> {
    fn from(value: SignatureBytes) -> Self {
        let sig = value
            .sig
            .map(|s| Scalar::from_bytes(&s).expect("Invalid scalar"));
        let r_pub_key = value
            .r_pub_key
            .map(|p| Point::from_bytes(&p).expect("Invalid point"));
        let challenge = value
            .challenge
            .map(|c| Scalar::from_bytes(&c).expect("Invalid scalar"));
        let index = value.index;
        let secret = None;
        let g_pub_key = value
            .g_pub_key
            .map(|p| Point::from_bytes(&p).expect("Invalid point"));

        Self {
            sig,
            r_pub_key,
            challenge,
            index,
            secret,
            g_pub_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    use sha2::Sha256;

    use crate::crypto::dkg::classic::Signature;

    type E = Secp256k1;
    type H = Sha256;

    #[test]
    fn return_default_signature() {
        let result = Signature::<E>::new();

        assert_eq!(result, Signature::default());
    }

    #[test]
    fn same_signature() {
        let signature = Scalar::<E>::random();

        let result = Signature::new().with_signature(signature.clone());

        assert_eq!(result.signature(), Some(&signature));
    }

    #[test]
    fn same_random_public_key() {
        let random_public_key = Point::<E>::zero();

        let result = Signature::new().with_random_public_key(random_public_key.clone());

        assert_eq!(result.random_public_key(), Some(&random_public_key));
    }

    #[test]
    fn same_global_public_key() {
        let expected = Point::<E>::zero();
        let sig = Signature::new().with_global_public_key(expected.clone());

        let result = sig.global_public_key();

        assert_eq!(result, Some(&expected));
    }

    #[test]
    fn with_keypair_sets_secret_and_global_public_key() {
        let secret = Scalar::<E>::random();
        let global_public_key = Point::<E>::generator() * &secret;

        let sig = Signature::new().with_keypair(secret.clone(), global_public_key.clone());

        assert_eq!(sig.secret(), Some(&secret));
        assert_eq!(sig.global_public_key(), Some(&global_public_key));
    }

    #[test]
    fn generate_signature_validates_correctly() {
        let secret = Scalar::<E>::random();
        let global_public_key = Point::<E>::generator() * &secret;
        let seed = b"test_seed";
        let message = b"test_message";

        let sig = Signature::new()
            .with_keypair(secret, global_public_key)
            .generate::<H>(seed, message);

        assert!(sig.signature().is_some());
        assert!(sig.random_public_key().is_some());
        assert!(sig.challenge().is_some());
        assert!(sig.validate());
    }

    #[test]
    fn set_index_and_retrieve() {
        let index = 42u16;
        let mut sig = Signature::<E>::new();

        sig.set_index(index);

        assert_eq!(sig.index(), Some(index));
    }

    #[test]
    fn aggregate_signatures_with_consistent_keys() {
        let secret1 = Scalar::<E>::random();
        let secret2 = Scalar::<E>::random();
        let global_public_key =
            Point::<E>::generator() * &secret1 + Point::<E>::generator() * &secret2;
        let seed = b"test_seed";
        let message = b"test_message";

        let mut sig1 = Signature::new()
            .with_keypair(secret1, global_public_key.clone())
            .generate::<H>(seed, message);
        sig1.set_index(1);

        let mut sig2 = Signature::new()
            .with_keypair(secret2, global_public_key.clone())
            .generate::<H>(seed, message);
        sig2.set_index(2);

        let aggregated = sig1.aggregate::<Sha256>(&[sig2.clone()]);

        assert!(aggregated.signature().is_some());
        assert_eq!(aggregated.random_public_key(), sig1.random_public_key());
        assert_eq!(aggregated.global_public_key(), sig1.global_public_key());
    }

    #[test]
    #[should_panic(expected = "Random public keys are different")]
    fn aggregate_fails_with_different_random_public_keys() {
        let secret = Scalar::<E>::random();
        let global_public_key = Point::<E>::generator() * &secret;
        let message = b"test_message";

        let mut sig1 = Signature::new()
            .with_keypair(secret.clone(), global_public_key.clone())
            .generate::<H>(b"seed1", message);
        sig1.set_index(1);

        let mut sig2 = Signature::new()
            .with_keypair(secret, global_public_key)
            .generate::<H>(b"seed2", message); // Different seed, different r_pub_key
        sig2.set_index(2);

        sig1.aggregate::<Sha256>(&[sig2]); // Should panic
    }

    #[test]
    fn signature_to_bytes_and_back() {
        let secret = Scalar::<E>::random();
        let global_public_key = Point::<E>::generator() * &secret;
        let seed = b"test_seed";
        let message = b"test_message";
        let original = Signature::new()
            .with_keypair(secret, global_public_key)
            .generate::<H>(seed, message);

        let bytes: Vec<u8> = original.clone().into();
        let restored = Signature::<E>::from(bytes.as_slice());

        assert_eq!(original.signature(), restored.signature());
        assert_eq!(original.random_public_key(), restored.random_public_key());
        assert_eq!(original.global_public_key(), restored.global_public_key());
        assert_eq!(original.challenge(), restored.challenge());
    }
}
