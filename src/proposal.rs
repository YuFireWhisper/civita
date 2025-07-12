use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use derivative::Derivative;

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
    traits::{serializable, Serializable},
};

type ProofDb = HashMap<Multihash, Vec<u8>>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
pub struct Diff {
    pub from: resident::Record,
    pub to: resident::Record,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct UnSignedProposal {
    pub code: u8,
    pub parent_root: Multihash,
    pub diff: BTreeMap<Vec<u8>, Diff>,
    pub total_stakes_diff: i32,
    pub proposer: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proofs: ProofDb,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
pub struct Proposal {
    unsigned: UnSignedProposal,
    proposer_sig: Signature,
    #[derivative(PartialEq = "ignore")]
    hash_cache: OnceLock<Multihash>,
}

impl UnSignedProposal {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        let input = self
            .to_vec()
            .expect("UnSignedProposal should be serializable");
        H::hash(&input)
    }
}

impl Proposal {
    pub fn new<H: Hasher>(unsigned: UnSignedProposal, sk: &SecretKey) -> Self {
        let hash = unsigned.hash::<H>();
        let proposer_sig = sk.sign(hash.to_bytes().as_slice());
        let hash_cache = OnceLock::new();
        hash_cache.set(hash).expect("Hash cache should be empty");

        Self {
            unsigned,
            proposer_sig,
            hash_cache,
        }
    }

    pub fn code(&self) -> u8 {
        self.unsigned.code
    }

    pub fn parent_root(&self) -> &Multihash {
        &self.unsigned.parent_root
    }

    pub fn diff(&self) -> &BTreeMap<Vec<u8>, Diff> {
        &self.unsigned.diff
    }

    pub fn total_stakes_diff(&self) -> i32 {
        self.unsigned.total_stakes_diff
    }

    pub fn proposer(&self) -> &PublicKey {
        &self.unsigned.proposer
    }

    pub fn proposer_data(&self) -> Option<&Vec<u8>> {
        self.unsigned.proposer_data.as_ref()
    }

    pub fn proofs(&self) -> &ProofDb {
        &self.unsigned.proofs
    }

    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| self.unsigned.hash::<H>())
    }

    pub fn proposer_sig(&self) -> &Signature {
        &self.proposer_sig
    }

    pub fn verify_signature<H: Hasher>(&self) -> bool {
        let hash = self.hash::<H>();
        self.proposer()
            .verify_signature(hash.to_bytes().as_slice(), self.proposer_sig())
    }
}

impl Serializable for Diff {
    fn serialized_size(&self) -> usize {
        self.from.serialized_size() + self.to.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let from = resident::Record::from_reader(reader)?;
        let to = resident::Record::from_reader(reader)?;
        Ok(Self { from, to })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.from.to_writer(writer)?;
        self.to.to_writer(writer)?;
        Ok(())
    }
}

impl Serializable for UnSignedProposal {
    fn serialized_size(&self) -> usize {
        unimplemented!(
            "Calculate size will very slowly, please just use Vec::new() without capacity"
        );
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let code = u8::from_reader(reader)?;
        let parent_root = Multihash::from_reader(reader)?;
        let diff = BTreeMap::<Vec<u8>, Diff>::from_reader(reader)?;
        let total_stakes_diff = i32::from_reader(reader)?;
        let proposer = PublicKey::from_reader(reader)?;
        let proposer_data = Option::<Vec<u8>>::from_reader(reader)?;
        let proofs = ProofDb::from_reader(reader)?;

        Ok(Self {
            code,
            parent_root,
            diff,
            total_stakes_diff,
            proposer,
            proposer_data,
            proofs,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.code.to_writer(writer)?;
        self.parent_root.to_writer(writer)?;
        self.diff.to_writer(writer)?;
        self.total_stakes_diff.to_writer(writer)?;
        self.proposer.to_writer(writer)?;
        self.proposer_data.to_writer(writer)?;
        self.proofs.to_writer(writer)?;

        Ok(())
    }
}

impl Serializable for Proposal {
    fn serialized_size(&self) -> usize {
        unimplemented!(
            "Calculate size will very slowly, please just use Vec::new() without capacity"
        );
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            unsigned: UnSignedProposal::from_reader(reader)?,
            proposer_sig: Signature::from_reader(reader)?,
            hash_cache: OnceLock::new(),
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.unsigned.to_writer(writer)?;
        self.proposer_sig.to_writer(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::SecretKey;

    use super::*;

    type TestHasher = sha2::Sha256;

    fn default_proposal() -> Proposal {
        let sk = SecretKey::random();
        let pk = sk.public_key();

        let unsigned = UnSignedProposal {
            code: 1,
            parent_root: Multihash::default(),
            diff: BTreeMap::new(),
            total_stakes_diff: 0,
            proposer: pk.clone(),
            proposer_data: None,
            proofs: ProofDb::new(),
        };

        Proposal::new::<TestHasher>(unsigned, &sk)
    }

    #[test]
    fn proposal_serialization() {
        let proposal = default_proposal();

        let enc = proposal.to_vec().expect("Proposal should be serializable");
        let dec = Proposal::from_slice(&enc).expect("Proposal should be deserializable");

        assert_eq!(
            proposal, dec,
            "Deserialized proposal should match the original"
        );
    }

    #[test]
    fn true_if_signature_is_valid() {
        let proposal = default_proposal();
        let is_valid = proposal.verify_signature::<TestHasher>();

        assert!(is_valid, "Proposal signature should be valid");
    }

    #[test]
    fn false_if_signature_is_invalid() {
        let mut proposal = default_proposal();
        proposal.unsigned.proposer = SecretKey::random().public_key();

        let is_valid = proposal.verify_signature::<TestHasher>();

        assert!(!is_valid, "Proposal signature should be invalid");
    }
}
