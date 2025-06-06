use bincode::{Decode, Encode};
use libecvrf_k256::ECVRF;
use serde::{Deserialize, Serialize};

mod secp256k1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("{0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("{0}")]
    Secpk1(#[from] secp256k1::Error),
}

#[derive(Debug)]
pub enum KeyType {
    Secp256k1,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Encode, Decode)]
#[derive(Hash)]
#[derive(Serialize, Deserialize)]
pub enum SecretKey {
    Secp256k1(secp256k1::SecretKey),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
#[derive(Encode, Decode)]
#[derive(Serialize, Deserialize)]
pub enum PublicKey {
    Secp256k1(secp256k1::PublicKey),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize, Deserialize)]
pub enum VrfProof {
    Secp256k1(libecvrf_k256::ECVRFProof),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Encode, Decode)]
#[derive(Serialize, Deserialize)]
pub enum ResidentSignature {
    Secp256k1(secp256k1::ResidentSignature),
}

impl SecretKey {
    pub fn to_public_key(&self) -> PublicKey {
        match self {
            SecretKey::Secp256k1(sk) => PublicKey::Secp256k1(sk.to_public_key()),
        }
    }

    pub fn decrypt(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match self {
            SecretKey::Secp256k1(sk) => sk.decrypt(msg).map_err(Error::from),
        }
    }

    pub fn prove(&self, msg: impl AsRef<[u8]>) -> Result<VrfProof> {
        match self {
            SecretKey::Secp256k1(sk) => Ok(VrfProof::Secp256k1(sk.prove(msg)?)),
        }
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<ResidentSignature> {
        match self {
            SecretKey::Secp256k1(sk) => Ok(ResidentSignature::Secp256k1(sk.sign(msg)?)),
        }
    }
}

impl PublicKey {
    pub fn encrypt(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        match self {
            PublicKey::Secp256k1(pk) => pk.encrypt(msg).map_err(Error::from),
        }
    }

    pub fn verify_proof(&self, msg: impl AsRef<[u8]>, proof: &VrfProof) -> bool {
        match (self, proof) {
            (PublicKey::Secp256k1(pk), VrfProof::Secp256k1(proof)) => pk.verify_proof(msg, proof),
        }
    }

    pub fn verify_signature(&self, msg: impl AsRef<[u8]>, sig: &ResidentSignature) -> bool {
        match (self, sig) {
            (PublicKey::Secp256k1(pk), ResidentSignature::Secp256k1(sig)) => {
                pk.verify_signature(msg, sig)
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    pub fn to_peer_id(&self) -> libp2p::PeerId {
        match self {
            PublicKey::Secp256k1(pk) => pk.to_peer_id(),
        }
    }
}

impl VrfProof {
    pub fn output(&self) -> [u8; 32] {
        match self {
            VrfProof::Secp256k1(proof) => proof.y.to_bytes().into(),
        }
    }

    pub fn verify(&self, msg: impl AsRef<[u8]>, public_key: impl AsRef<[u8]>) -> bool {
        match self {
            VrfProof::Secp256k1(proof) => ECVRF::verify(msg.as_ref(), proof, public_key.as_ref()),
        }
    }
}

pub fn generate_keypair(t: KeyType) -> (SecretKey, PublicKey) {
    match t {
        KeyType::Secp256k1 => generate_secp256k1(),
    }
}

pub fn generate_secp256k1() -> (SecretKey, PublicKey) {
    let (sk, pk) = secp256k1::generate_keypair();
    (SecretKey::Secp256k1(sk), PublicKey::Secp256k1(pk))
}

impl From<secp256k1::SecretKey> for SecretKey {
    fn from(secret_key: secp256k1::SecretKey) -> Self {
        SecretKey::Secp256k1(secret_key)
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            SecretKey::Secp256k1(sk) => sk.as_ref(),
        }
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(public_key: secp256k1::PublicKey) -> Self {
        PublicKey::Secp256k1(public_key)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            PublicKey::Secp256k1(pk) => pk.as_ref(),
        }
    }
}

impl From<SecretKey> for PublicKey {
    fn from(secret_key: SecretKey) -> Self {
        match secret_key {
            SecretKey::Secp256k1(sk) => PublicKey::Secp256k1(sk.to_public_key()),
        }
    }
}

impl From<SecretKey> for libp2p::identity::Keypair {
    fn from(secret_key: SecretKey) -> Self {
        match secret_key {
            SecretKey::Secp256k1(sk) => sk.into(),
        }
    }
}
