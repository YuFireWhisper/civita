use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
};

type ProofDb = HashMap<Multihash, Vec<u8>>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Diff {
    pub from: resident::Record,
    pub to: resident::Record,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Payload {
    pub code: u8,
    pub parent_root: Multihash,
    pub diff: BTreeMap<Vec<u8>, Diff>,
    pub total_stakes_diff: i32,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proposal_stakes: u32,

    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Witness {
    pub sig: Signature,
    pub proofs: ProofDb,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Proposal {
    pub payload: Payload,
    pub witness: Witness,
}

impl Payload {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn sign<H: Hasher>(&self, sk: &SecretKey) -> Signature {
        sk.sign(&self.hash::<H>().to_bytes())
    }
}

impl Proposal {
    pub fn new(payload: Payload, witness: Witness) -> Self {
        Self { payload, witness }
    }

    pub fn verify_signature<H: Hasher>(&self) -> bool {
        let msg = self.payload.hash::<H>().to_bytes();
        self.payload
            .proposer_pk
            .verify_signature(&msg, &self.witness.sig)
    }
}
//
// impl Serializable for Diff {
//     fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
//         let from = resident::Record::from_reader(reader)?;
//         let to = resident::Record::from_reader(reader)?;
//         Ok(Self { from, to })
//     }
//
//     fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
//         self.from.to_writer(writer);
//         self.to.to_writer(writer);
//     }
// }

// impl Serializable for Payload {
//     fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
//         let code = u8::from_reader(reader)?;
//         let parent_root = Multihash::from_reader(reader)?;
//         let diff = BTreeMap::<Vec<u8>, Diff>::from_reader(reader)?;
//         let total_stakes_diff = i32::from_reader(reader)?;
//         let proposer_pk = PublicKey::from_reader(reader)?;
//         let proposer_data = Option::<Vec<u8>>::from_reader(reader)?;
//         let proposal_stakes = u32::from_reader(reader)?;
//
//         Ok(Self {
//             code,
//             parent_root,
//             diff,
//             total_stakes_diff,
//             proposer_pk,
//             proposer_data,
//             proposal_stakes,
//             hash_cache: OnceLock::new(),
//         })
//     }
//
//     fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
//         self.code.to_writer(writer);
//         self.parent_root.to_writer(writer);
//         self.diff.to_writer(writer);
//         self.total_stakes_diff.to_writer(writer);
//         self.proposer_pk.to_writer(writer);
//         self.proposer_data.to_writer(writer);
//         self.proposal_stakes.to_writer(writer);
//     }
// }
//
// impl Serializable for Witness {
//     fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
//         let sig = Signature::from_reader(reader)?;
//         let proofs = ProofDb::from_reader(reader)?;
//         Ok(Self { sig, proofs })
//     }
//
//     fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
//         self.sig.to_writer(writer);
//         self.proofs.to_writer(writer);
//     }
// }
//
// impl Serializable for Proposal {
//     fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
//         Ok(Self {
//             payload: Payload::from_reader(reader)?,
//             witness: Witness::from_reader(reader)?,
//         })
//     }
//
//     fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
//         self.payload.to_writer(writer);
//         self.witness.to_writer(writer);
//     }
// }

// #[cfg(test)]
// mod tests {
//     use crate::crypto::SecretKey;
//
//     use super::*;
//
//     type TestHasher = sha2::Sha256;
//
//     fn setup() -> Proposal {
//         let sk = SecretKey::random();
//         let pk = sk.public_key();
//
//         let payload = Payload {
//             code: 1,
//             parent_root: Multihash::default(),
//             diff: BTreeMap::new(),
//             total_stakes_diff: 0,
//             proposer_pk: pk.clone(),
//             proposer_data: None,
//             proposal_stakes: 0,
//             hash_cache: OnceLock::new(),
//         };
//
//         let witness = create_witness_with_sk(&payload, &sk);
//
//         Proposal::new(payload, witness)
//     }
//
//     fn create_witness_with_sk(payload: &Payload, sk: &SecretKey) -> Witness {
//         let sig = payload.sign::<TestHasher>(sk);
//         let proofs = ProofDb::new();
//
//         Witness { sig, proofs }
//     }
//
//     #[test]
//     fn payload_serialization() {
//         let prop = setup();
//         let payload = prop.payload.clone();
//
//         let enc = payload.to_vec();
//         let dec = Payload::from_slice(&enc).expect("Payload should be deserializable");
//
//         assert_eq!(
//             payload, dec,
//             "Deserialized payload should match the original"
//         );
//     }
//
//     #[test]
//     fn witness_serialization() {
//         let prop = setup();
//         let witness = prop.witness.clone();
//
//         let enc = witness.to_vec();
//         let dec = Witness::from_slice(&enc).expect("Witness should be deserializable");
//
//         assert_eq!(
//             witness, dec,
//             "Deserialized witness should match the original"
//         );
//     }
//
//     #[test]
//     fn proposal_serialization() {
//         let prop = setup();
//
//         let enc = prop.to_vec();
//         let dec = Proposal::from_slice(&enc).expect("Proposal should be deserializable");
//
//         assert_eq!(prop, dec, "Deserialized proposal should match the original");
//     }
//
//     #[test]
//     fn true_if_signature_is_valid() {
//         let prop = setup();
//
//         let is_valid = prop.verify_signature::<TestHasher>();
//
//         assert!(is_valid, "Proposal signature should be valid");
//     }
//
//     #[test]
//     fn false_if_signature_is_invalid() {
//         let mut prop = setup();
//         let other = SecretKey::random();
//         prop.witness = create_witness_with_sk(&prop.payload, &other);
//
//         let is_valid = prop.verify_signature::<TestHasher>();
//
//         assert!(
//             !is_valid,
//             "Proposal signature should be invalid after changing the code"
//         );
//     }
// }
