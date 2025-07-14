use std::{
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    resident,
    utils::mpt::{self, ProofResult, Trie},
};

type ProofDb = HashMap<Multihash, Vec<u8>>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0:?}")]
    Vdf(vdf::InvalidIterations),

    #[error(transparent)]
    Mpt(#[from] mpt::Error),
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Diff {
    pub from: Option<resident::Record>,
    pub to: resident::Record,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Payload {
    pub code: u8,
    pub parent: Multihash,
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
#[derive(Serialize)]
pub struct Witness {
    pub sig: Signature,
    pub proofs: ProofDb,
    pub vdf_proof: Vec<u8>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Proposal {
    payload: Payload,
    witness: Witness,
}

impl Payload {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn sign<H: Hasher>(&self, sk: &SecretKey) -> Signature {
        sk.sign(&self.hash::<H>().to_bytes())
    }
}

impl Witness {
    pub fn new(sig: Signature, proofs: ProofDb, vdf_proof: Vec<u8>) -> Self {
        Self {
            sig,
            proofs,
            vdf_proof,
        }
    }

    pub fn from_payload<H: Hasher, S: mpt::Storage>(
        payload: &Payload,
        sk: &SecretKey,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: &Trie<H, S>,
    ) -> Result<Self> {
        let hash = payload.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = ProofDb::new();
        for key in payload.diff.keys() {
            mpt.prove(key, &mut proofs)?;
        }

        let vdf_proof = vdf
            .solve(&hash, vdf_difficulty)
            .expect("VDF proof should be valid");

        Ok(Self {
            sig,
            proofs,
            vdf_proof,
        })
    }
}

impl Proposal {
    pub fn new(payload: Payload, witness: Witness) -> Self {
        Self { payload, witness }
    }

    pub fn verify<H: Hasher>(
        &self,
        root_hash: &Multihash,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
    ) -> bool {
        if &self.payload.parent != root_hash {
            return false;
        }

        let hash = self.payload.hash::<H>().to_bytes();

        if !self
            .payload
            .proposer_pk
            .verify_signature(&hash, &self.witness.sig)
        {
            return false;
        }

        if vdf
            .verify(&hash, vdf_difficulty, &self.witness.vdf_proof)
            .is_err()
        {
            return false;
        }

        if !self.verify_proposer::<H>(*root_hash) {
            return false;
        }

        if !self.verify_diff(*root_hash) {
            return false;
        }

        true
    }

    fn verify_proposer<H: Hasher>(&self, root_hash: Multihash) -> bool {
        let key = self.payload.proposer_pk.to_hash::<H>().to_bytes();

        let Some(ProofResult::Exists(bytes)) =
            mpt::verify_proof_with_hash(&key, &self.witness.proofs, root_hash)
        else {
            return false;
        };

        let record = resident::Record::from_slice(&bytes)
            .expect("Bytes is from root hash, it should be valid");

        record.stakes == self.payload.proposal_stakes
    }

    fn verify_diff(&self, root_hash: Multihash) -> bool {
        for (key, diff) in &self.payload.diff {
            let Some(res) = mpt::verify_proof_with_hash(key, &self.witness.proofs, root_hash)
            else {
                return false;
            };

            let from = diff
                .from
                .as_ref()
                .map_or(ProofResult::NotExists, |r| ProofResult::Exists(r.to_vec()));

            if res != from {
                return false;
            }
        }

        true
    }

    pub fn parent(&self) -> Multihash {
        self.payload.parent
    }

    pub fn proposer_stakes(&self) -> u32 {
        self.payload.proposal_stakes
    }
}

#[cfg(test)]
mod tests {
    use vdf::{VDFParams, WesolowskiVDFParams};

    use super::*;

    type TestHasher = sha2::Sha256;
    type Trie = mpt::Trie<TestHasher, HashMap<Multihash, Vec<u8>>>;

    #[test]
    fn success_create_witness_from_payload() {
        let sk = SecretKey::random();
        let proposer_pk = sk.public_key();

        let mut mpt = Trie::empty(HashMap::new());

        let key = proposer_pk.to_hash::<TestHasher>().to_bytes();

        let from = resident::Record {
            stakes: 100,
            data: vec![1, 2, 3],
        };

        let to = resident::Record {
            stakes: 200,
            data: vec![4, 5, 6],
        };

        mpt.update(&key, from.to_vec()).unwrap();
        let root_hash = mpt.commit().unwrap();

        let mut diff = BTreeMap::new();
        diff.insert(
            key,
            Diff {
                from: Some(from),
                to,
            },
        );

        let payload = Payload {
            code: 0,
            parent: root_hash,
            diff,
            total_stakes_diff: 100,
            proposer_pk,
            proposer_data: None,
            proposal_stakes: 100,
            hash_cache: OnceLock::new(),
        };

        let vdf = WesolowskiVDFParams(2048).new();
        let vdf_difficulty = 0;

        let witness =
            Witness::from_payload::<TestHasher, _>(&payload, &sk, &vdf, vdf_difficulty, &mpt)
                .unwrap();

        let proposal = Proposal::new(payload, witness);

        let is_valid = proposal.verify::<TestHasher>(&root_hash, &vdf, vdf_difficulty);

        assert!(is_valid, "Witness should be valid");
    }
}
