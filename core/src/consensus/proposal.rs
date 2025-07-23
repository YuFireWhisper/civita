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
    utils::trie::{self, ProofResult, Record, Trie, Weight},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Diff {
    pub from: Option<Record>,
    pub to: Record,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Proposal {
    pub code: u8,
    pub parent: Multihash,
    pub diffs: BTreeMap<Vec<u8>, Diff>,
    pub proposer_pk: PublicKey,
    pub proposer_data: Option<Vec<u8>>,
    pub proposer_weight: Weight,
    #[serialize(skip)]
    hash_cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct Witness {
    pub sig: Signature,
    pub proofs: HashMap<Multihash, Vec<u8>>,
    pub vdf_proof: Vec<u8>,
}

#[derive(Default)]
pub struct Builder {
    pub code: u8,
    pub parent: Option<Multihash>,
    pub diffs: BTreeMap<Vec<u8>, Diff>,
    pub proposer_pk: Option<PublicKey>,
    pub proposer_data: Option<Vec<u8>>,
    pub proposer_weight: Option<Weight>,
}

impl Diff {
    pub fn new(from: Option<Record>, to: Record) -> Self {
        Diff { from, to }
    }
}

impl Proposal {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_witness<H: Hasher>(
        &self,
        sk: &SecretKey,
        trie: &Trie<H>,
        vdf: &WesolowskiVDF,
        vdf_difficulty: u64,
    ) -> Result<Witness> {
        let hash = self.hash::<H>().to_bytes();

        let sig = sk.sign(&hash);
        let proofs = self.generate_proofs::<H>(trie);
        let vdf_proof = vdf
            .solve(&hash, vdf_difficulty)
            .expect("VDF proof should be valid");

        Ok(Witness::new(sig, proofs, vdf_proof))
    }

    pub fn generate_proofs<H: Hasher>(&self, trie: &Trie<H>) -> HashMap<Multihash, Vec<u8>> {
        let mut proofs = HashMap::new();

        self.diffs
            .keys()
            .chain(std::iter::once(&self.proposer_pk.to_hash::<H>().to_bytes()))
            .for_each(|key| {
                trie.prove(key, &mut proofs);
            });

        proofs
    }

    pub fn verify_signature<H: Hasher>(&self, witness: &Witness) -> bool {
        let hash = self.hash::<H>().to_bytes();
        self.proposer_pk.verify_signature(&hash, &witness.sig)
    }

    pub fn verify_vdf<H: Hasher>(
        &self,
        witness: &Witness,
        vdf: &WesolowskiVDF,
        difficulty: u64,
    ) -> bool {
        let hash = self.hash::<H>().to_bytes();
        vdf.verify(&hash, difficulty, &witness.vdf_proof).is_ok()
    }

    pub fn verify_proposer_weight<H: Hasher>(
        &self,
        witness: &Witness,
        trie_root: Multihash,
    ) -> bool {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();
        Self::verify_proof(
            &key,
            trie_root,
            &witness.proofs,
            Some(self.proposer_weight),
            None,
        )
    }

    fn verify_proof(
        key: &[u8],
        trie_root: Multihash,
        proofs: &HashMap<Multihash, Vec<u8>>,
        exp_weight: Option<Weight>,
        exp_record: Option<&Record>,
    ) -> bool {
        match trie::verify_proof_with_hash(key, proofs, trie_root) {
            ProofResult::Exists(record) => {
                if let Some(exp_record) = exp_record {
                    record == *exp_record
                } else {
                    record.weight == exp_weight.unwrap_or(0)
                }
            }
            ProofResult::NotExists => exp_weight.unwrap_or(0) == 0 && exp_record.is_none(),
            ProofResult::Invalid => false,
        }
    }

    pub fn verify_diffs<H: Hasher>(&self, witness: &Witness, trie_root: Multihash) -> bool {
        self.diffs.iter().all(|(key, diff)| {
            Self::verify_proof(key, trie_root, &witness.proofs, None, diff.from.as_ref())
        })
    }
}

impl Witness {
    pub fn new(sig: Signature, proofs: HashMap<Multihash, Vec<u8>>, vdf_proof: Vec<u8>) -> Self {
        Witness {
            sig,
            proofs,
            vdf_proof,
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_code(mut self, code: u8) -> Self {
        self.code = code;
        self
    }

    pub fn with_parent(mut self, parent: Multihash) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn with_diff(mut self, key: Vec<u8>, diff: Diff) -> Self {
        self.diffs.insert(key, diff);
        self
    }

    pub fn with_diffs(mut self, diffs: BTreeMap<Vec<u8>, Diff>) -> Self {
        self.diffs = diffs;
        self
    }

    pub fn with_proposer_pk(mut self, pk: PublicKey) -> Self {
        self.proposer_pk = Some(pk);
        self
    }

    pub fn with_proposer_data(mut self, data: Vec<u8>) -> Self {
        self.proposer_data = Some(data);
        self
    }

    pub fn with_proposer_data_opt(mut self, data: Option<Vec<u8>>) -> Self {
        self.proposer_data = data;
        self
    }

    pub fn with_proposer_weight(mut self, weight: Weight) -> Self {
        self.proposer_weight = Some(weight);
        self
    }

    pub fn build(self) -> Option<Proposal> {
        let parent = self.parent?;
        let proposer_pk = self.proposer_pk?;
        let proposer_weight = self.proposer_weight?;

        Some(Proposal {
            code: self.code,
            parent,
            diffs: self.diffs,
            proposer_pk,
            proposer_data: self.proposer_data,
            proposer_weight,
            hash_cache: OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use vdf::{VDFParams, WesolowskiVDFParams};

    use super::*;

    type TestHasher = sha2::Sha256;
    type Trie = trie::Trie<TestHasher>;

    const CODE: u8 = 0;
    const FROM_WEIGHT: Weight = 100;
    const TO_WEIGHT: Weight = 200;
    const PROPOSER_WEIGHT: Weight = 100;

    const VDF_PARAMS: WesolowskiVDFParams = WesolowskiVDFParams(1024);
    const VDF_DIFFICULTY: u64 = 1;

    fn setup() -> (Proposal, Witness, Multihash) {
        let from_sk = SecretKey::random();
        let from_pk = from_sk.public_key();
        let from_pk_bytes = from_pk.to_hash::<TestHasher>().to_bytes();

        let proposer_sk = SecretKey::random();
        let proposer_pk = proposer_sk.public_key();
        let proposer_pk_bytes = proposer_pk.to_hash::<TestHasher>().to_bytes();

        let from = Record {
            weight: FROM_WEIGHT,
            data: vec![1, 2, 3],
        };

        let to = Record {
            weight: TO_WEIGHT,
            data: vec![4, 5, 6],
        };

        let proposer_record = Record {
            weight: PROPOSER_WEIGHT,
            data: vec![7, 8, 9],
        };

        let mut trie = Trie::empty();
        trie.update(&from_pk_bytes, from.clone(), None);
        trie.update(&proposer_pk_bytes, proposer_record, None);
        let root_hash = trie.commit();

        let diff = Diff {
            from: Some(from),
            to,
        };

        let mut diffs = BTreeMap::new();
        diffs.insert(from_pk_bytes, diff);

        let prop = Proposal {
            code: CODE,
            parent: Multihash::default(),
            diffs,
            proposer_pk,
            proposer_data: None,
            proposer_weight: PROPOSER_WEIGHT,
            hash_cache: OnceLock::new(),
        };

        let vdf = VDF_PARAMS.new();

        let witness = prop
            .generate_witness(&proposer_sk, &trie, &vdf, VDF_DIFFICULTY)
            .expect("Witness generation should succeed");

        (prop, witness, root_hash)
    }

    fn random_signature() -> Signature {
        let sk = SecretKey::random();
        let msg = vec![0; 32];
        sk.sign(&msg)
    }

    #[test]
    fn veirfy_signature() {
        let (prop, witness, _) = setup();

        let invalid_winess = Witness {
            sig: random_signature(),
            ..witness.clone()
        };

        assert!(prop.verify_signature::<TestHasher>(&witness));
        assert!(!prop.verify_signature::<TestHasher>(&invalid_winess));
    }

    #[test]
    fn verify_vdf() {
        let (prop, witness, _) = setup();

        let vdf = VDF_PARAMS.new();

        let invalid_witness = Witness {
            vdf_proof: vec![0; 32], // Invalid proof
            ..witness.clone()
        };

        assert!(prop.verify_vdf::<TestHasher>(&witness, &vdf, VDF_DIFFICULTY));
        assert!(!prop.verify_vdf::<TestHasher>(&invalid_witness, &vdf, VDF_DIFFICULTY));
    }
}
