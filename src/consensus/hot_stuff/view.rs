use std::{
    collections::{BTreeSet, HashMap},
    io::{Cursor, Read},
};

use derivative::Derivative;

use crate::{
    consensus::randomizer::{self, DrawProof},
    crypto::{
        self,
        traits::{hasher::HashArray, PublicKey, Suite},
        Hasher,
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Randomizer(#[from] randomizer::Error),

    #[error("{0}")]
    Crypto(#[from] crypto::Error),
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
#[derivative(Clone(bound = ""))]
#[derivative(Eq(bound = ""), PartialEq(bound = ""))]
pub struct Block<H: Hasher> {
    pub root_hash: HashArray<H>,
    pub total_stakes: u32,
    pub proposals: BTreeSet<Vec<u8>>,
    pub records: BTreeSet<HashArray<H>>,
}

#[derive(Derivative)]
#[derivative(Debug)]
#[derivative(Clone)]
#[derivative(Eq, PartialEq)]
pub struct QuorumCertificate<S: Suite> {
    pub view_number: u64,
    pub block_hash: HashArray<S::Hasher>,
    pub leader: (S::PublicKey, DrawProof<S::Proof>),
    pub validators: HashMap<S::PublicKey, DrawProof<S::Proof>>,
}

#[derive(Derivative)]
#[derivative(Debug)]
#[derivative(Clone)]
#[derivative(Eq, PartialEq)]
pub struct View<S: Suite> {
    pub number: u64,
    pub block: Block<S::Hasher>,
    pub leader: (S::PublicKey, DrawProof<S::Proof>),
    pub parent: QuorumCertificate<S>,
}

impl<H: Hasher> Block<H> {
    pub fn hash(&self) -> HashArray<H> {
        H::hash(self.to_bytes().as_slice())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(self.root_hash.as_slice());
        bytes.extend(self.total_stakes.to_le_bytes());

        self.serialize_proposals(&mut bytes);
        self.serialize_records(&mut bytes);

        bytes
    }

    fn serialize_proposals(&self, bytes: &mut Vec<u8>) {
        bytes.extend((self.proposals.len() as u32).to_le_bytes());

        self.proposals.iter().for_each(|proposal| {
            bytes.extend((proposal.len() as u32).to_le_bytes());
            bytes.extend_from_slice(proposal);
        });
    }

    fn serialize_records(&self, bytes: &mut Vec<u8>) {
        bytes.extend((self.records.len() as u32).to_le_bytes());

        self.records.iter().for_each(|record| {
            bytes.extend_from_slice(record.as_slice());
        });
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::from_cursor(&mut Cursor::new(slice))
    }

    pub fn from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Block {
            root_hash: read_hash_array::<H>(cursor)?,
            total_stakes: read_u32(cursor)?,
            proposals: Self::deserialize_proposals(cursor)?,
            records: Self::deserialize_records(cursor)?,
        })
    }

    fn deserialize_proposals(cursor: &mut Cursor<&[u8]>) -> Result<BTreeSet<Vec<u8>>> {
        let count = read_u32(cursor)?;

        let mut proposals = BTreeSet::new();

        for _ in 0..count {
            let length = read_u32(cursor)? as usize;
            let mut proposal = vec![0u8; length];
            cursor.read_exact(&mut proposal)?;
            proposals.insert(proposal);
        }

        Ok(proposals)
    }

    fn deserialize_records(cursor: &mut Cursor<&[u8]>) -> Result<BTreeSet<HashArray<H>>> {
        let count = read_u32(cursor)?;

        let mut records = BTreeSet::new();

        for _ in 0..count {
            let record = read_hash_array::<H>(cursor)?;
            records.insert(record);
        }

        Ok(records)
    }
}

impl<S: Suite> QuorumCertificate<S> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.view_number.to_le_bytes());
        bytes.extend_from_slice(self.block_hash.as_slice());

        write_leader_and_size_info::<S>(&mut bytes, &self.leader);
        self.serialize_validators(&mut bytes);

        bytes
    }

    fn serialize_validators(&self, bytes: &mut Vec<u8>) {
        bytes.extend((self.validators.len() as u32).to_le_bytes());

        self.validators.iter().for_each(|(pk, proof)| {
            bytes.extend(pk.to_bytes());
            bytes.extend(proof.to_bytes());
        })
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        Self::from_cursor(&mut Cursor::new(slice))
    }

    fn from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let view_number = read_u64(cursor)?;
        let block_hash = read_hash_array::<S::Hasher>(cursor)?;

        let (pk_size, proof_size) = read_size_info::<S>(cursor)?;
        let leader = read_public_key_and_proof::<S>(pk_size, proof_size, cursor)?;

        let validators = Self::deserialize_validators(pk_size, proof_size, cursor)?;

        Ok(QuorumCertificate {
            view_number,
            block_hash,
            leader,
            validators,
        })
    }

    fn deserialize_validators(
        pk_size: u32,
        result_size: u32,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<HashMap<S::PublicKey, DrawProof<S::Proof>>> {
        let count = read_u32(cursor)?;
        let mut validators = HashMap::new();

        for _ in 0..count {
            let (pk, proof) = read_public_key_and_proof::<S>(pk_size, result_size, cursor)?;
            validators.insert(pk, proof);
        }

        Ok(validators)
    }
}

impl<S: Suite> View<S> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.number.to_le_bytes());
        bytes.extend(self.block.to_bytes());

        write_leader_and_size_info::<S>(&mut bytes, &self.leader);
        bytes.extend(self.parent.to_bytes());

        bytes
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(slice);

        let number = read_u64(&mut cursor)?;
        let block = Block::<S::Hasher>::from_cursor(&mut cursor)?;

        let (pk_size, proof_size) = read_size_info::<S>(&mut cursor)?;
        let leader = read_public_key_and_proof::<S>(pk_size, proof_size, &mut cursor)?;
        let parent = QuorumCertificate::<S>::from_cursor(&mut cursor)?;

        Ok(View {
            number,
            block,
            leader,
            parent,
        })
    }
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_hash_array<H: Hasher>(cursor: &mut Cursor<&[u8]>) -> Result<HashArray<H>> {
    let mut hash_array = HashArray::<H>::default();
    cursor.read_exact(hash_array.as_mut_slice())?;
    Ok(hash_array)
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn read_public_key<S: Suite>(pk_size: u32, cursor: &mut Cursor<&[u8]>) -> Result<S::PublicKey> {
    let mut pk_bytes = vec![0u8; pk_size as usize];
    cursor.read_exact(&mut pk_bytes)?;
    S::PublicKey::from_slice(&pk_bytes).map_err(Error::from)
}

fn read_draw_proof<S: Suite>(
    proof_size: u32,
    cursor: &mut Cursor<&[u8]>,
) -> Result<DrawProof<S::Proof>> {
    let mut proof_bytes = vec![0u8; proof_size as usize];
    cursor.read_exact(&mut proof_bytes)?;
    DrawProof::from_slice(&proof_bytes).map_err(Error::from)
}

fn read_size_info<S: Suite>(cursor: &mut Cursor<&[u8]>) -> Result<(u32, u32)> {
    let pk_size = read_u32(cursor)?;
    let result_size = read_u32(cursor)?;
    Ok((pk_size, result_size))
}

fn read_public_key_and_proof<S: Suite>(
    pk_size: u32,
    proof_size: u32,
    cursor: &mut Cursor<&[u8]>,
) -> Result<(S::PublicKey, DrawProof<S::Proof>)> {
    let pk = read_public_key::<S>(pk_size, cursor)?;
    let proof = read_draw_proof::<S>(proof_size, cursor)?;
    Ok((pk, proof))
}

fn write_leader_and_size_info<S: Suite>(
    bytes: &mut Vec<u8>,
    leader: &(S::PublicKey, DrawProof<S::Proof>),
) {
    let pk_bytes = leader.0.to_bytes();
    let proof_bytes = leader.1.to_bytes();

    bytes.extend((pk_bytes.len() as u32).to_le_bytes());
    bytes.extend((proof_bytes.len() as u32).to_le_bytes());

    bytes.extend(pk_bytes);
    bytes.extend(proof_bytes);
}
