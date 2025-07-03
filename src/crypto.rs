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
pub enum Suite {
    Secp256k1,
    Secp256r1,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum PublicKey {
    Secp256k1(short_weierstrass::Affine<ark_secp256k1::Config>),
    Secp256r1(short_weierstrass::Affine<ark_secp256r1::Config>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum SecretKey {
    Secp256k1(ec::SecretKey<ark_secp256k1::Config>),
    Secp256r1(ec::SecretKey<ark_secp256r1::Config>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Signature {
    Secp256k1(ec::Signature<short_weierstrass::Affine<ark_secp256k1::Config>, ark_secp256k1::Fr>),
    Secp256r1(ec::Signature<short_weierstrass::Affine<ark_secp256r1::Config>, ark_secp256r1::Fr>),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub enum Proof {
    Secp256k1(ec::vrf::Proof<short_weierstrass::Affine<ark_secp256k1::Config>, ark_secp256k1::Fr>),
    Secp256r1(ec::vrf::Proof<short_weierstrass::Affine<ark_secp256r1::Config>, ark_secp256r1::Fr>),
}

impl PublicKey {
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Secp256k1(_) => Suite::Secp256k1,
            PublicKey::Secp256r1(_) => Suite::Secp256r1,
        }
    }

    pub fn verify_signature(&self, msg: &[u8], sig: &Signature) -> bool {
        match (self, sig) {
            (PublicKey::Secp256k1(pk), Signature::Secp256k1(sig)) => pk.verify_signature(msg, sig),
            (PublicKey::Secp256r1(pk), Signature::Secp256r1(sig)) => pk.verify_signature(msg, sig),
            _ => false,
        }
    }

    pub fn verify_proof(&self, alpha: &[u8], proof: &Proof) -> bool {
        match (self, proof) {
            (PublicKey::Secp256k1(pk), Proof::Secp256k1(proof)) => pk.verify_proof(alpha, proof),
            (PublicKey::Secp256r1(pk), Proof::Secp256r1(proof)) => pk.verify_proof(alpha, proof),
            _ => false,
        }
    }

    pub fn to_hash<H: Hasher>(&self) -> Multihash {
        match self {
            PublicKey::Secp256k1(pk) => {
                H::hash(&pk.to_vec().expect("PublicKey should be serializable"))
            }
            PublicKey::Secp256r1(pk) => {
                H::hash(&pk.to_vec().expect("PublicKey should be serializable"))
            }
        }
    }
}

impl SecretKey {
    pub fn suite(&self) -> Suite {
        match self {
            SecretKey::Secp256k1(_) => Suite::Secp256k1,
            SecretKey::Secp256r1(_) => Suite::Secp256r1,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        match self {
            SecretKey::Secp256k1(sk) => Signature::Secp256k1(sk.sign(msg)),
            SecretKey::Secp256r1(sk) => Signature::Secp256r1(sk.sign(msg)),
        }
    }

    pub fn prove(&self, alpha: &[u8]) -> Proof {
        match self {
            SecretKey::Secp256k1(sk) => Proof::Secp256k1(sk.prove(alpha)),
            SecretKey::Secp256r1(sk) => Proof::Secp256r1(sk.prove(alpha)),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            SecretKey::Secp256k1(sk) => PublicKey::Secp256k1(sk.public_key()),
            SecretKey::Secp256r1(sk) => PublicKey::Secp256r1(sk.public_key()),
        }
    }
}

impl Signature {
    pub fn suite(&self) -> Suite {
        match self {
            Signature::Secp256k1(_) => Suite::Secp256k1,
            Signature::Secp256r1(_) => Suite::Secp256r1,
        }
    }
}

impl Proof {
    pub fn suite(&self) -> Suite {
        match self {
            Proof::Secp256k1(_) => Suite::Secp256k1,
            Proof::Secp256r1(_) => Suite::Secp256r1,
        }
    }

    pub fn to_hash<H: Hasher>(&self) -> Multihash {
        match self {
            Proof::Secp256k1(proof) => proof.proof_to_hash::<H>(),
            Proof::Secp256r1(proof) => proof.proof_to_hash::<H>(),
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
            1 => Ok(Suite::Secp256r1),
            _ => Err(serializable::Error("Unknown suite".to_string())),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        match self {
            Suite::Secp256k1 => 0u8.to_writer(writer),
            Suite::Secp256r1 => 1u8.to_writer(writer),
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
                PublicKey::Secp256k1(pk) => {
                    short_weierstrass::Affine::<ark_secp256k1::Config>::SIZE
                }
                PublicKey::Secp256r1(pk) => {
                    short_weierstrass::Affine::<ark_secp256r1::Config>::SIZE
                }
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(PublicKey::Secp256k1(short_weierstrass::Affine::<
                ark_secp256k1::Config,
            >::from_reader(reader))),
            Suite::Secp256r1 => Ok(PublicKey::Secp256r1(short_weierstrass::Affine::<
                ark_secp256r1::Config,
            >::from_reader(reader))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            PublicKey::Secp256k1(pk) => pk.to_writer(writer),
            PublicKey::Secp256r1(pk) => pk.to_writer(writer),
        }
    }
}

impl Serializable for SecretKey {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                SecretKey::Secp256k1(sk) => ec::SecretKey::<ark_secp256k1::Config>::SIZE,
                SecretKey::Secp256r1(sk) => ec::SecretKey::<ark_secp256r1::Config>::SIZE,
            }
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let suite = Suite::from_reader(reader)?;

        match suite {
            Suite::Secp256k1 => Ok(SecretKey::Secp256k1(
                ec::SecretKey::<ark_secp256k1::Config>::from_reader(reader),
            )),
            Suite::Secp256r1 => Ok(SecretKey::Secp256r1(
                ec::SecretKey::<ark_secp256r1::Config>::from_reader(reader),
            )),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            SecretKey::Secp256k1(sk) => sk.to_writer(writer),
            SecretKey::Secp256r1(sk) => sk.to_writer(writer),
        }
    }
}

impl Serializable for Signature {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                Signature::Secp256k1(sig) => {
                    ec::Signature::<
                        short_weierstrass::Affine<ark_secp256k1::Config>,
                        ark_secp256k1::Fr,
                    >::SIZE
                }
                Signature::Secp256r1(sig) => {
                    ec::Signature::<
                        short_weierstrass::Affine<ark_secp256r1::Config>,
                        ark_secp256r1::Fr,
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
            >::from_reader(reader))),
            Suite::Secp256r1 => Ok(Signature::Secp256r1(ec::Signature::<
                short_weierstrass::Affine<ark_secp256r1::Config>,
                ark_secp256r1::Fr,
            >::from_reader(reader))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            Signature::Secp256k1(sig) => sig.to_writer(writer),
            Signature::Secp256r1(sig) => sig.to_writer(writer),
        }
    }
}

impl Serializable for Proof {
    fn serialized_size(&self) -> usize {
        Suite::SIZE
            + match self {
                Proof::Secp256k1(proof) => {
                    ec::vrf::Proof::<
                        short_weierstrass::Affine<ark_secp256k1::Config>,
                        ark_secp256k1::Fr,
                    >::SIZE
                }
                Proof::Secp256r1(proof) => {
                    ec::vrf::Proof::<
                        short_weierstrass::Affine<ark_secp256r1::Config>,
                        ark_secp256r1::Fr,
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
            >::from_reader(reader))),
            Suite::Secp256r1 => Ok(Proof::Secp256r1(ec::vrf::Proof::<
                short_weierstrass::Affine<ark_secp256r1::Config>,
                ark_secp256r1::Fr,
            >::from_reader(reader))),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.suite().to_writer(writer)?;

        match self {
            Proof::Secp256k1(proof) => proof.to_writer(writer),
            Proof::Secp256r1(proof) => proof.to_writer(writer),
        }
    }
}
