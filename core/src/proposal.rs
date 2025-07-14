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
pub struct Proposal {
    pub code: u8,
    pub parent: Multihash,
    pub parent_checkpoint: Multihash,
    pub diffs: BTreeMap<Vec<u8>, Diff>,
    pub total_weight_diff: i32,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proposer_weight: u32,
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

impl Proposal {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn sign<H: Hasher>(&self, sk: &SecretKey) -> Signature {
        sk.sign(&self.hash::<H>().to_bytes())
    }

    pub fn generate_witness<H: Hasher, S: mpt::Storage>(
        &self,
        sk: &SecretKey,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
        mpt: &Trie<H, S>,
    ) -> Result<Witness> {
        let hash = self.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);

        let mut proofs = ProofDb::new();
        for key in self.diffs.keys() {
            mpt.prove(key, &mut proofs)?;
        }

        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        mpt.prove(&key, &mut proofs)?;

        let vdf_proof = vdf
            .solve(&hash, vdf_difficulty)
            .expect("VDF proof should be valid");

        Ok(Witness {
            sig,
            proofs,
            vdf_proof,
        })
    }

    pub fn verify<H: Hasher>(
        &self,
        witness: &Witness,
        parent: &Multihash,
        checkpoint: &Multihash,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
    ) -> bool {
        if &self.parent != parent || &self.parent_checkpoint != checkpoint {
            return false;
        }

        let hash = self.hash::<H>().to_bytes();

        if !self.proposer_pk.verify_signature(&hash, &witness.sig) {
            return false;
        }

        if vdf
            .verify(&hash, vdf_difficulty, &witness.vdf_proof)
            .is_err()
        {
            return false;
        }

        if !self.verify_proposer::<H>(&witness.proofs) {
            return false;
        }

        if !self.verify_diff(&witness.proofs) {
            return false;
        }

        true
    }

    fn verify_proposer<H: Hasher>(&self, proofs: &ProofDb) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        let exp = (self.proposer_weight != 0).then_some(self.proposer_weight);
        self.verify_proof(&key, proofs, exp, None)
    }

    fn verify_proof(
        &self,
        key: &[u8],
        proofs: &ProofDb,
        exp_weight: Option<u32>,
        exp_record: Option<&resident::Record>,
    ) -> bool {
        let Some(res) = mpt::verify_proof_with_hash(key, proofs, self.parent) else {
            return false;
        };

        let ProofResult::Exists(resident_bytes) = res else {
            // If the proof does not exist, we expect no record
            return exp_weight.is_none() && exp_record.is_none();
        };

        let record = resident::Record::from_slice(&resident_bytes)
            .expect("Bytes is from root hash, it should be valid");

        let exp_weight = exp_weight.map_or(0, |w| w);

        if record.weight != exp_weight {
            return false;
        }

        if let Some(exp_record) = exp_record {
            if &record != exp_record {
                return false;
            }
        }

        true
    }

    fn verify_diff(&self, proofs: &ProofDb) -> bool {
        self.diffs
            .iter()
            .all(|(key, diff)| self.verify_proof(key, proofs, None, diff.from.as_ref()))
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
            weight: 100,
            data: vec![1, 2, 3],
        };

        let to = resident::Record {
            weight: 200,
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

        let prop = Proposal {
            code: 0,
            parent: root_hash,
            parent_checkpoint: root_hash,
            diffs: diff,
            total_weight_diff: 100,
            proposer_pk,
            proposer_data: None,
            proposer_weight: 100,
            hash_cache: OnceLock::new(),
        };

        let vdf = WesolowskiVDFParams(2048).new();
        let vdf_difficulty = 0;

        let witness = prop
            .generate_witness(&sk, &vdf, vdf_difficulty, &mpt)
            .expect("Witness generation should succeed");

        let is_valid =
            prop.verify::<TestHasher>(&witness, &root_hash, &root_hash, &vdf, vdf_difficulty);

        assert!(is_valid, "Witness should be valid");
    }
}
