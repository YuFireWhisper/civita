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
    utils::trie::{self, ProofResult, Trie},
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
    pub proofs: HashMap<Multihash, Vec<u8>>,
    pub vdf_proof: Vec<u8>,
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
        let proofs = self
            .generate_proofs::<H>(trie)
            .expect("Failed to generate proofs");
        let vdf_proof = vdf
            .solve(&hash, vdf_difficulty)
            .expect("VDF proof should be valid");

        Ok(Witness::new(sig, proofs, vdf_proof))
    }

    fn generate_proofs<H: Hasher>(&self, trie: &Trie<H>) -> Option<HashMap<Multihash, Vec<u8>>> {
        let mut proofs = HashMap::new();

        let all_proved = self
            .diffs
            .keys()
            .chain(std::iter::once(&self.proposer_pk.to_hash::<H>().to_bytes()))
            .all(|key| trie.prove(key, &mut proofs));

        all_proved.then_some(proofs)
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
        let proofs = &witness.proofs;
        Self::verify_proof(&key, trie_root, proofs, Some(self.proposer_weight), None)
    }

    pub fn verify_diffs(&self, witness: &Witness, trie_root: Multihash) -> bool {
        self.diffs.iter().all(|(key, diff)| {
            Self::verify_proof(key, trie_root, &witness.proofs, None, diff.from.as_ref())
        })
    }

    fn verify_proof(
        key: &[u8],
        trie_root: Multihash,
        proofs: &HashMap<Multihash, Vec<u8>>,
        exp_weight: Option<u32>,
        exp_record: Option<&resident::Record>,
    ) -> bool {
        match trie::verify_proof_with_hash(key, proofs, trie_root) {
            ProofResult::Exists(bytes) => {
                let record = resident::Record::from_slice(&bytes)
                    .expect("Bytes is from root hash, it should be valid");

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

// #[cfg(test)]
// mod tests {
//     use std::collections::BTreeSet;
//
//     use vdf::{VDFParams, WesolowskiVDFParams};
//
//     use super::*;
//
//     type TestHasher = sha2::Sha256;
//     type Trie = trie::Trie<TestHasher>;
//
//     const CODE: u8 = 0;
//     const FROM_WEIGHT: u32 = 100;
//     const TO_WEIGHT: u32 = 200;
//     const PROPOSER_WEIGHT: u32 = 100;
//
//     const HEIGHT: u64 = 2;
//
//     const VDF_PARAMS: WesolowskiVDFParams = WesolowskiVDFParams(1024);
//     const VDF_DIFFICULTY: u64 = 1;
//
//     fn setup() -> (Proposal, Witness, Block, Block, Multihash) {
//         let from_sk = SecretKey::random();
//         let from_pk = from_sk.public_key();
//         let from_pk_bytes = from_pk.to_hash::<TestHasher>().to_bytes();
//
//         let proposer_sk = SecretKey::random();
//         let proposer_pk = proposer_sk.public_key();
//         let proposer_pk_bytes = proposer_pk.to_hash::<TestHasher>().to_bytes();
//
//         let from = resident::Record {
//             weight: FROM_WEIGHT,
//             data: vec![1, 2, 3],
//         };
//
//         let to = resident::Record {
//             weight: TO_WEIGHT,
//             data: vec![4, 5, 6],
//         };
//
//         let proposer_record = resident::Record {
//             weight: PROPOSER_WEIGHT,
//             data: vec![7, 8, 9],
//         };
//
//         let mut trie = Trie::empty();
//         trie.update(&from_pk_bytes, from.to_vec(), None);
//         trie.update(&proposer_pk_bytes, proposer_record.to_vec(), None);
//         let root_hash = trie.commit();
//
//         let diff = Diff {
//             from: Some(from),
//             to,
//         };
//
//         let mut diffs = BTreeMap::new();
//         diffs.insert(from_pk_bytes, diff);
//
//         let parent = setup_block(BTreeSet::new(), HEIGHT);
//         let parent_hash = parent.hash::<TestHasher>();
//
//         let parent_checkpoint = setup_block(BTreeSet::new(), HEIGHT - 1);
//         let parent_checkpoint_hash = parent_checkpoint.hash::<TestHasher>();
//
//         let prop = Proposal {
//             code: CODE,
//             parent: parent_hash,
//             parent_checkpoint: parent_checkpoint_hash,
//             diffs,
//             total_weight_diff: TO_WEIGHT as i32 - FROM_WEIGHT as i32,
//             proposer_pk,
//             proposer_data: None,
//             proposer_weight: PROPOSER_WEIGHT,
//             hash_cache: OnceLock::new(),
//         };
//
//         let vdf = VDF_PARAMS.new();
//
//         let witness = prop
//             .generate_witness(&proposer_sk, &trie, &vdf, VDF_DIFFICULTY)
//             .expect("Witness generation should succeed");
//
//         (prop, witness, parent, parent_checkpoint, root_hash)
//     }
//
//     fn setup_block(proposals: BTreeSet<Multihash>, height: u64) -> Block {
//         let proposer_sk = SecretKey::random();
//         let proposer_pk = proposer_sk.public_key();
//
//         Block {
//             proposals,
//             parent: Multihash::default(),
//             parent_checkpoint: Multihash::default(),
//             height,
//             proposer_pk,
//             proposer_weight: PROPOSER_WEIGHT,
//             hash_cache: OnceLock::new(),
//         }
//     }
//
//     #[test]
//     fn success_verify() {
//         let (prop, witness, _, _, root_hash) = setup();
//
//         let vdf = VDF_PARAMS.new();
//
//         assert!(prop.verify_signature::<TestHasher>(&witness));
//         assert!(prop.verify_vdf::<TestHasher>(&witness, &vdf, VDF_DIFFICULTY));
//         assert!(prop.verify_proposer_weight::<TestHasher>(&witness, root_hash));
//         assert!(prop.verify_diffs(&witness, root_hash));
//     }
// }
