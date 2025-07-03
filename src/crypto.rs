use ark_ec::short_weierstrass;

use crate::{
    crypto::traits::{
        vrf::{Proof as _, Prover as _, VerifyProof},
        SecretKey as _, Signer as _, VerifiySignature,
    },
    traits::{serializable, ConstantSize, Serializable},
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
                H::hash(&pk.to_vec().expect("PublicKey should be serializable"))
            }
        }
    }

    pub fn to_peer_id(&self) -> libp2p::PeerId {
        match self {
            PublicKey::Secp256k1(pk) => {
                let pk = libp2p::identity::secp256k1::PublicKey::try_from_bytes(
                    &pk.to_vec().expect("PublicKey should be serializable"),
                )
                .expect("Failed to convert PublicKey to libp2p Secp256k1 PublicKey");

                let pk = libp2p::identity::PublicKey::from(pk);

                libp2p::PeerId::from_public_key(&pk)
            }
        }
    }
}

impl SecretKey {
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
                let sk = libp2p::identity::secp256k1::SecretKey::try_from_bytes(
                    sk.to_vec().expect("SecretKey should be serializable"),
                )
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
    fn serialized_size(&self) -> usize {
        u8::SIZE
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        match u8::from_reader(reader)? {
            0 => Ok(Suite::Secp256k1),
            _ => Err(serializable::Error("Unknown suite".to_string())),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        match self {
            Suite::Secp256k1 => 0u8.to_writer(writer),
        }
    }
}

impl ConstantSize for Suite {
    const SIZE: usize = 1;
}

impl Serializable for PublicKey {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                PublicKey::Secp256k1(_) => short_weierstrass::Affine::<ark_secp256k1::Config>::SIZE,
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(PublicKey::Secp256k1(short_weierstrass::Affine::<
                ark_secp256k1::Config,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            PublicKey::Secp256k1(pk) => pk.to_writer(writer),
        }
    }
}

impl Serializable for SecretKey {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                SecretKey::Secp256k1(_) => ec::SecretKey::<ark_secp256k1::Config>::SIZE,
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(SecretKey::Secp256k1(
                ec::SecretKey::<ark_secp256k1::Config>::from_reader(reader)?,
            )),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            SecretKey::Secp256k1(sk) => sk.to_writer(writer),
        }
    }
}

impl Serializable for Signature {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                Signature::Secp256k1(_) => {
                    ec::Signature::<
                        short_weierstrass::Affine<ark_secp256k1::Config>,
                        ark_secp256k1::Fr,
                    >::SIZE
                }
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(Signature::Secp256k1(ec::Signature::<
                short_weierstrass::Affine<ark_secp256k1::Config>,
                ark_secp256k1::Fr,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            Signature::Secp256k1(sig) => sig.to_writer(writer),
        }
    }
}

impl Serializable for Proof {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                Proof::Secp256k1(_) => {
                    ec::vrf::Proof::<
                        short_weierstrass::Affine<ark_secp256k1::Config>,
                        ark_secp256k1::Fr,
                    >::SIZE
                }
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(Proof::Secp256k1(ec::vrf::Proof::<
                short_weierstrass::Affine<ark_secp256k1::Config>,
                ark_secp256k1::Fr,
            >::from_reader(reader)?)),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            Proof::Secp256k1(proof) => proof.to_writer(writer),
        }
    }
}
