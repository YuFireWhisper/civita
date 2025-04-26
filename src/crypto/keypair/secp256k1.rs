use bincode::{Decode, Encode};
use k256::{
    elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
    schnorr::signature::{hazmat::PrehashSigner, Verifier},
    PublicKey as K256PublicKey, SecretKey as K256SecretKey,
};
use serde::{Deserialize, Serialize};

const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;
const SIGNATURE_LENGTH: usize = 64;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    EllipticCurve(#[from] k256::elliptic_curve::Error),

    #[error("{0}")]
    Ecies(String),

    #[error("{0}")]
    Ecvrf(String),

    #[error("{0}")]
    Schnorr(#[from] k256::schnorr::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LENGTH]);

#[derive(Clone)]
#[derive(Debug)]
#[derive(Encode, Decode)]
#[derive(PartialEq, Eq)]
pub struct ResidentSignature([u8; SIGNATURE_LENGTH]);

impl SecretKey {
    pub fn random() -> Self {
        let secret_key: K256SecretKey = K256SecretKey::random(&mut OsRng);
        Self::from(&secret_key)
    }

    pub fn to_public_key(&self) -> PublicKey {
        self.into()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ecies::decrypt(&self.0, ciphertext).map_err(|e| Error::Ecies(e.to_string()))
    }

    pub fn prove(&self, input: impl AsRef<[u8]>) -> Result<libecvrf_k256::ECVRFProof> {
        let ecvrf = libecvrf_k256::ECVRF::new_from_bytes(&self.0)
            .map_err(|e| Error::Ecvrf(e.to_string()))?;

        ecvrf
            .prove(input.as_ref())
            .map_err(|e| Error::Ecvrf(e.to_string()))
    }

    pub fn sign(&self, msg: &[u8]) -> Result<ResidentSignature> {
        let secret_key = self.to_k256_secret_key();
        let signing_key: k256::schnorr::SigningKey = secret_key.into();
        let signature = signing_key.sign_prehash(msg)?;

        Ok(signature.into())
    }

    pub fn to_k256_secret_key(&self) -> K256SecretKey {
        self.into()
    }
}

impl PublicKey {
    pub fn random() -> Self {
        let secret_key = SecretKey::random();
        Self::from_secret_key(&secret_key)
    }

    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        Self::from(secret_key)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Self::try_from(bytes)
    }

    pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        ecies::encrypt(&self.0, msg).map_err(|e| Error::Ecies(e.to_string()))
    }

    pub fn verify_proof(&self, input: impl AsRef<[u8]>, proof: &libecvrf_k256::ECVRFProof) -> bool {
        libecvrf_k256::ECVRF::verify(input.as_ref(), proof, &self.0)
    }

    pub fn verify_signature(&self, msg: &[u8], signature: &ResidentSignature) -> bool {
        let public_key = self.to_k256_public_key();
        let verifying_key: k256::schnorr::VerifyingKey = public_key
            .try_into()
            .expect("Failed to convert public key to verifying key");
        verifying_key.verify(msg, &signature.into()).is_ok()
    }

    pub fn to_k256_public_key(&self) -> K256PublicKey {
        self.into()
    }
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::random();
    let public_key = PublicKey::from_secret_key(&secret_key);
    (secret_key, public_key)
}

impl From<&k256::SecretKey> for SecretKey {
    fn from(secret_key: &k256::SecretKey) -> Self {
        Self(secret_key.to_bytes().into())
    }
}

impl From<&SecretKey> for k256::SecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        k256::SecretKey::from_slice(secret_key.as_ref()).expect("Invalid secret key")
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let key = K256SecretKey::from_slice(bytes)?;
        Ok(Self::from(&key))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&k256::PublicKey> for PublicKey {
    fn from(public_key: &k256::PublicKey) -> Self {
        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&public_key.to_encoded_point(true).to_bytes());
        Self(arr)
    }
}

impl From<&PublicKey> for k256::PublicKey {
    fn from(public_key: &PublicKey) -> Self {
        k256::PublicKey::from_sec1_bytes(public_key.as_ref()).expect("Invalid public key")
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let secret_key = secret_key.to_k256_secret_key();
        let public_key = secret_key.public_key();
        Self::from(&public_key)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let key = K256PublicKey::from_sec1_bytes(bytes)?;

        let mut arr = [0u8; PUBLIC_KEY_LENGTH];
        arr.copy_from_slice(&key.to_encoded_point(true).to_bytes());

        Ok(Self(arr))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&k256::schnorr::Signature> for ResidentSignature {
    fn from(signature: &k256::schnorr::Signature) -> Self {
        let signature_bytes = signature.to_bytes();
        Self(signature_bytes.into())
    }
}

impl From<k256::schnorr::Signature> for ResidentSignature {
    fn from(signature: k256::schnorr::Signature) -> Self {
        let signature_bytes = signature.to_bytes();
        Self(signature_bytes.into())
    }
}

impl From<&ResidentSignature> for k256::schnorr::Signature {
    fn from(signature: &ResidentSignature) -> Self {
        k256::schnorr::Signature::try_from(signature.as_ref()).expect("Invalid signature")
    }
}

impl TryFrom<&[u8]> for ResidentSignature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let signature = k256::schnorr::Signature::try_from(bytes)?;
        Ok(Self::from(signature))
    }
}

impl AsRef<[u8]> for ResidentSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = <Vec<u8>>::deserialize(deserializer)?;

        PublicKey::from_slice(&bytes)
            .map_err(|e| D::Error::custom(format!("Invalid public key: {}", e)))
    }
}

impl Serialize for ResidentSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ResidentSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        ResidentSignature::try_from(bytes.as_slice())
            .map_err(|e| D::Error::custom(format!("Invalid signature: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::keypair::secp256k1::{
        PublicKey, ResidentSignature, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
        SIGNATURE_LENGTH,
    };

    #[test]
    fn generate_keypair_is_valid() {
        let (sk, pk) = super::generate_keypair();

        assert_eq!(sk.as_ref().len(), SECRET_KEY_LENGTH);
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn encrypt_decrypt() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk, pk) = super::generate_keypair();
        let ciphertext = pk.encrypt(MESSAGE).expect("Encryption failed");
        let decrypted = sk.decrypt(&ciphertext).expect("Decryption failed");

        assert_eq!(decrypted, MESSAGE);
    }

    #[test]
    fn fails_with_invalid_keys() {
        let invalid_public_key = vec![0u8; 0];
        assert!(PublicKey::from_slice(&invalid_public_key).is_err());
    }

    #[test]
    fn different_keys() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk1, pk1) = super::generate_keypair();
        let (sk2, pk2) = super::generate_keypair();

        assert_ne!(sk1, sk2);
        assert_ne!(pk1, pk2);

        let ciphertext = pk1.encrypt(MESSAGE).expect("Encryption failed");
        assert!(
            sk2.decrypt(&ciphertext).is_err(),
            "Decryption should fail with different keys"
        );
    }

    #[test]
    fn vrf_success() {
        const MESSAGE: &[u8] = b"Hello, world!";

        let (sk, pk) = super::generate_keypair();
        let proof = sk.prove(MESSAGE);
        assert!(proof.is_ok(), "VRF proof generation failed");
        assert!(
            pk.verify_proof(MESSAGE, &proof.unwrap()),
            "VRF proof verification failed"
        );
    }

    #[test]
    fn secret_key_random_creates_unique_keys() {
        let sk1 = SecretKey::random();
        let sk2 = SecretKey::random();
        assert_ne!(sk1, sk2, "Randomly generated secret keys should be unique");
    }

    #[test]
    fn secret_key_from_slice_valid_data_succeeds() {
        let original = SecretKey::random();
        let bytes = original.as_ref();
        let recovered = SecretKey::from_slice(bytes).expect("Should parse valid key data");
        assert_eq!(original, recovered);
    }

    #[test]
    fn secret_key_from_slice_invalid_size_fails() {
        let too_short = vec![0u8; SECRET_KEY_LENGTH - 1];
        assert!(SecretKey::from_slice(&too_short).is_err());

        let too_long = vec![0u8; SECRET_KEY_LENGTH + 1];
        assert!(SecretKey::from_slice(&too_long).is_err());
    }

    #[test]
    fn secret_key_from_slice_invalid_data_fails() {
        let zeros = vec![0u8; SECRET_KEY_LENGTH];
        assert!(SecretKey::from_slice(&zeros).is_err());
    }

    #[test]
    fn public_key_from_secret_key_is_consistent() {
        let sk = SecretKey::random();
        let pk1 = sk.to_public_key();
        let pk2 = PublicKey::from_secret_key(&sk);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn public_key_from_slice_valid_data_succeeds() {
        let original = PublicKey::random();
        let bytes = original.as_ref();
        let recovered = PublicKey::from_slice(bytes).expect("Should parse valid key data");
        assert_eq!(original, recovered);
    }

    #[test]
    fn public_key_from_slice_invalid_size_fails() {
        let too_short = vec![0u8; PUBLIC_KEY_LENGTH - 1];
        assert!(PublicKey::from_slice(&too_short).is_err());

        let too_long = vec![0u8; PUBLIC_KEY_LENGTH + 1];
        assert!(PublicKey::from_slice(&too_long).is_err());
    }

    #[test]
    fn public_key_from_slice_invalid_format_fails() {
        let invalid = vec![0x04; PUBLIC_KEY_LENGTH];
        assert!(PublicKey::from_slice(&invalid).is_err());
    }

    #[test]
    fn encrypt_decrypt_empty_message_works() {
        let (sk, pk) = super::generate_keypair();
        let empty_message = b"";
        let ciphertext = pk
            .encrypt(empty_message)
            .expect("Empty message encryption failed");
        let decrypted = sk
            .decrypt(&ciphertext)
            .expect("Empty message decryption failed");
        assert_eq!(&decrypted, empty_message);
    }

    #[test]
    fn encrypt_decrypt_large_message_works() {
        let large_message = vec![b'A'; 1024 * 1024]; // 1MB of data
        let (sk, pk) = super::generate_keypair();

        let ciphertext = pk
            .encrypt(&large_message)
            .expect("Large message encryption failed");
        let decrypted = sk
            .decrypt(&ciphertext)
            .expect("Large message decryption failed");

        assert_eq!(decrypted, large_message);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let message = b"secret message";
        let (_, pk1) = super::generate_keypair();
        let (sk2, _) = super::generate_keypair();

        let ciphertext = pk1.encrypt(message).expect("Encryption failed");
        let result = sk2.decrypt(&ciphertext);

        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let message = b"secret message";
        let (sk, pk) = super::generate_keypair();

        let mut ciphertext = pk.encrypt(message).expect("Encryption failed");

        if !ciphertext.is_empty() {
            let len = ciphertext.len();
            ciphertext[len / 2] ^= 0xFF;
        }

        let result = sk.decrypt(&ciphertext);

        assert!(
            result.is_err(),
            "Decryption of tampered ciphertext should fail"
        );
    }

    #[test]
    fn sign_verify_signature_succeeds() {
        let message = b"message to be signed";
        let (sk, pk) = super::generate_keypair();

        let signature = sk.sign(message).expect("Signing failed");
        let is_valid = pk.verify_signature(message, &signature);

        assert!(is_valid, "Signature verification should succeed");
    }

    #[test]
    fn verify_signature_different_message_fails() {
        let original_message = b"original message";
        let different_message = b"different message";
        let (sk, pk) = super::generate_keypair();

        let signature = sk.sign(original_message).expect("Signing failed");
        let is_valid = pk.verify_signature(different_message, &signature);

        assert!(
            !is_valid,
            "Signature verification should fail with different message"
        );
    }

    #[test]
    fn verify_signature_wrong_public_key_fails() {
        let message = b"message to sign";
        let (sk, _) = super::generate_keypair();
        let (_, pk2) = super::generate_keypair();

        let signature = sk.sign(message).expect("Signing failed");
        let is_valid = pk2.verify_signature(message, &signature);

        assert!(
            !is_valid,
            "Signature verification should fail with wrong public key"
        );
    }

    #[test]
    fn resident_signature_try_from_invalid_data_fails() {
        let invalid_data = [0u8; SIGNATURE_LENGTH - 1];
        let result = ResidentSignature::try_from(invalid_data.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn resident_signature_conversion_roundtrip() {
        let message = b"test message";
        let (sk, _) = super::generate_keypair();

        let signature = sk.sign(message).expect("Signing failed");
        let k256_sig: k256::schnorr::Signature = (&signature).into();
        let roundtrip_sig: ResidentSignature = (&k256_sig).into();

        assert_eq!(
            signature, roundtrip_sig,
            "Signature conversion roundtrip failed"
        );
    }

    #[test]
    fn vrf_same_input_same_output() {
        let input = b"test input";
        let (sk, pk) = super::generate_keypair();

        let proof1 = sk.prove(input).expect("VRF proof generation failed");
        let proof2 = sk.prove(input).expect("VRF proof generation failed");

        assert!(pk.verify_proof(input, &proof1), "First proof should verify");
        assert!(
            pk.verify_proof(input, &proof2),
            "Second proof should verify"
        );
    }

    #[test]
    fn vrf_different_input_different_output() {
        let input1 = b"input one";
        let input2 = b"input two";
        let (sk, pk) = super::generate_keypair();

        let proof1 = sk.prove(input1).expect("VRF proof generation failed");
        let proof2 = sk.prove(input2).expect("VRF proof generation failed");

        assert_ne!(
            &proof1, &proof2,
            "Different inputs should produce different proofs"
        );
        assert!(
            pk.verify_proof(input1, &proof1),
            "First proof should verify with first input"
        );
        assert!(
            !pk.verify_proof(input2, &proof1),
            "First proof should not verify with second input"
        );
        assert!(
            !pk.verify_proof(input1, &proof2),
            "Second proof should not verify with first input"
        );
    }

    #[test]
    fn vrf_proof_wrong_key_fails() {
        let input = b"test input";
        let (sk1, _) = super::generate_keypair();
        let (_, pk2) = super::generate_keypair();

        let proof = sk1.prove(input).expect("VRF proof generation failed");

        assert!(
            !pk2.verify_proof(input, &proof),
            "Proof should not verify with wrong key"
        );
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        let original = PublicKey::random();

        let json = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: PublicKey = serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(
            original, deserialized,
            "JSON serialization roundtrip failed"
        );

        let encoded = bincode::encode_to_vec(&original, bincode::config::standard())
            .expect("Bincode encoding failed");
        let (decoded, _): (PublicKey, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard())
                .expect("Bincode decoding failed");
        assert_eq!(original, decoded, "Bincode serialization roundtrip failed");
    }

    #[test]
    fn invalid_public_key_deserialization_fails() {
        let invalid_json = r#"[1, 2, 3]"#; // Too short
        let result: Result<PublicKey, _> = serde_json::from_str(invalid_json);
        assert!(
            result.is_err(),
            "Deserializing invalid public key should fail"
        );
    }

    #[test]
    fn resident_signature_serialization_roundtrip() {
        let message = b"message to sign";
        let (sk, _) = super::generate_keypair();
        let original = sk.sign(message).expect("Signing failed");

        let json = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: ResidentSignature =
            serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(
            original, deserialized,
            "JSON serialization roundtrip failed"
        );

        let encoded = bincode::encode_to_vec(&original, bincode::config::standard())
            .expect("Bincode encoding failed");
        let (decoded, _): (ResidentSignature, _) =
            bincode::decode_from_slice(&encoded, bincode::config::standard())
                .expect("Bincode decoding failed");
        assert_eq!(original, decoded, "Bincode serialization roundtrip failed");
    }

    #[test]
    fn invalid_signature_deserialization_fails() {
        let invalid_json = r#"[1, 2, 3]"#; // Too short
        let result: Result<ResidentSignature, _> = serde_json::from_str(invalid_json);
        assert!(
            result.is_err(),
            "Deserializing invalid signature should fail"
        );
    }

    #[test]
    fn should_not_reuse_keys_for_different_purposes() {
        let (sk, pk) = super::generate_keypair();
        let message = b"important message";

        let ciphertext = pk.encrypt(message).expect("Encryption failed");
        let decrypted = sk.decrypt(&ciphertext).expect("Decryption failed");
        assert_eq!(&decrypted, message);

        let signature = sk.sign(message).expect("Signing failed");
        assert!(pk.verify_signature(message, &signature));

        let proof = sk.prove(message).expect("VRF proof generation failed");
        assert!(pk.verify_proof(message, &proof));
    }

    #[test]
    fn when_converted_keys_maintain_original_properties() {
        let (sk, pk) = super::generate_keypair();

        let k256_sk = sk.to_k256_secret_key();
        let k256_pk = pk.to_k256_public_key();

        let recovered_sk = SecretKey::from(&k256_sk);
        let recovered_pk = PublicKey::from(&k256_pk);

        assert_eq!(
            sk, recovered_sk,
            "Secret key should remain the same after conversion"
        );
        assert_eq!(
            pk, recovered_pk,
            "Public key should remain the same after conversion"
        );
    }
}
