use ark_ec::short_weierstrass;

use crate::{
    crypto::traits::{
        vrf::{Proof as _, Prover as _, VerifyProof},
        SecretKey as _, Signer as _, VerifiySignature,
    },
    traits::{serializable, Serializable},
};

mod ec;
mod traits;

pub use traits::hasher::{Hasher, Multihash};

#[derive(Clone, Copy)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
pub enum Suite {
    Secp256k1,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
pub enum PublicKey {
    Secp256k1(short_weierstrass::Affine<ark_secp256k1::Config>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
pub enum SecretKey {
    Secp256k1(ec::SecretKey<ark_secp256k1::Config>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
pub enum Signature {
    Secp256k1(ec::Signature<short_weierstrass::Affine<ark_secp256k1::Config>, ark_secp256k1::Fr>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Hash)]
pub enum Proof {
    Secp256k1(ec::vrf::Proof<short_weierstrass::Affine<ark_secp256k1::Config>, ark_secp256k1::Fr>),
}

impl PublicKey {
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Secp256k1(_) => Suite::Secp256k1,
        }
    }

    pub fn verify_signature(&self, msg: &[u8], sig: &Signature) -> bool {
        match (self, sig) {
            (PublicKey::Secp256k1(pk), Signature::Secp256k1(sig)) => pk.verify_signature(msg, sig),
        }
    }

    pub fn verify_proof(&self, alpha: &[u8], proof: &Proof) -> bool {
        match (self, proof) {
            (PublicKey::Secp256k1(pk), Proof::Secp256k1(proof)) => pk.verify_proof(alpha, proof),
        }
    }

    pub fn to_hash<H: Hasher>(&self) -> Multihash {
        match self {
            PublicKey::Secp256k1(pk) => {
                // pk size is 32, so don't need to hash it
                Multihash::wrap(0, &pk.to_vec()).expect("Failed to wrap PublicKey into Multihash")
            }
        }
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .expect("PublicKey should be comparable")
    }
}

impl SecretKey {
    pub fn random() -> Self {
        SecretKey::Secp256k1(ec::SecretKey::<ark_secp256k1::Config>::random())
    }

    pub fn suite(&self) -> Suite {
        match self {
            SecretKey::Secp256k1(_) => Suite::Secp256k1,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SecretKey::Secp256k1(sk) => Signature::Secp256k1(sk.sign(msg)),
        }
    }

    pub fn prove(&self, alpha: &[u8]) -> Proof {
        match self {
            SecretKey::Secp256k1(sk) => Proof::Secp256k1(sk.prove(alpha)),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            SecretKey::Secp256k1(sk) => PublicKey::Secp256k1(sk.public_key()),
        }
    }

    pub fn to_libp2p_key(&self) -> libp2p::identity::Keypair {
        match self {
            SecretKey::Secp256k1(sk) => {
                let sk = libp2p::identity::secp256k1::SecretKey::try_from_bytes(sk.to_vec())
                    .expect("Failed to convert SecretKey to libp2p Secp256k1 SecretKey");
                libp2p::identity::secp256k1::Keypair::from(sk).into()
            }
        }
    }
}

impl Signature {
    pub fn suite(&self) -> Suite {
        match self {
            Signature::Secp256k1(_) => Suite::Secp256k1,
        }
    }
}

impl Proof {
    pub fn suite(&self) -> Suite {
        match self {
            Proof::Secp256k1(_) => Suite::Secp256k1,
        }
    }

    pub fn to_hash(&self) -> Multihash {
        match self {
            Proof::Secp256k1(proof) => proof.proof_to_hash(),
        }
    }
}

impl Serializable for Suite {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        match u8::from_reader(reader)? {
            0 => Ok(Suite::Secp256k1),
            _ => Err(serializable::Error("Unknown suite".to_string())),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        match self {
            Suite::Secp256k1 => 0u8.to_writer(writer),
        }
    }
}

impl Serializable for PublicKey {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(PublicKey::Secp256k1(short_weierstrass::Affine::<
                ark_secp256k1::Config,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.suite().to_writer(writer);

        match self {
            PublicKey::Secp256k1(pk) => pk.to_writer(writer),
        }
    }
}

impl Serializable for SecretKey {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(SecretKey::Secp256k1(
                ec::SecretKey::<ark_secp256k1::Config>::from_reader(reader)?,
            )),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.suite().to_writer(writer);

        match self {
            SecretKey::Secp256k1(sk) => sk.to_writer(writer),
        }
    }
}

impl Serializable for Signature {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(Signature::Secp256k1(ec::Signature::<
                short_weierstrass::Affine<ark_secp256k1::Config>,
                ark_secp256k1::Fr,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.suite().to_writer(writer);

        match self {
            Signature::Secp256k1(sig) => sig.to_writer(writer),
        }
    }
}

impl Serializable for Proof {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(Proof::Secp256k1(ec::vrf::Proof::<
                short_weierstrass::Affine<ark_secp256k1::Config>,
                ark_secp256k1::Fr,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.suite().to_writer(writer);

        match self {
            Proof::Secp256k1(proof) => proof.to_writer(writer),
        }
    }
}
