use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;
use vdf::{WesolowskiVDF, VDF};

use crate::{
    crypto::{Hasher, Multihash, PublicKey, SecretKey, Signature},
    utils::{
        trie::{self, ProofResult, Trie},
        Record,
    },
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {}

#[derive(Clone)]
#[derive(Serialize)]
#[derive(Derivative)]
#[derivative(Eq, PartialEq)]
pub struct Proposal<T: Record> {
    pub parent: Multihash,
    pub checkpoint: Multihash,
    pub dependencies: HashSet<Multihash>,
    pub operations: BTreeMap<Vec<u8>, T::Operation>,
    pub proposer_pk: PublicKey,
    pub metadata: Option<Vec<u8>>,
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

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Builder<T: Record> {
    pub parent: Option<Multihash>,
    pub checkpoint: Option<Multihash>,
    pub dependencies: HashSet<Multihash>,
    pub operations: BTreeMap<Vec<u8>, T::Operation>,
    pub proposer_pk: Option<PublicKey>,
    pub metadata: Option<Vec<u8>>,
}

impl<T: Record> Proposal<T> {
    pub fn hash<H: Hasher>(&self) -> Multihash {
        *self.hash_cache.get_or_init(|| H::hash(&self.to_vec()))
    }

    pub fn generate_witness<H: Hasher>(
        &self,
        sk: &SecretKey,
        trie: &Trie<H, T>,
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

    pub fn generate_proofs<H: Hasher>(&self, trie: &Trie<H, T>) -> HashMap<Multihash, Vec<u8>> {
        let mut proofs = HashMap::new();

        self.operations
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
        std::panic::catch_unwind(|| vdf.verify(&hash, difficulty, &witness.vdf_proof).is_ok())
            .unwrap_or(false)
    }

    pub fn verify_proposer_weight<H: Hasher>(
        &self,
        witness: &Witness,
        trie_root: Multihash,
    ) -> Option<T::Weight> {
        let key = self.proposer_pk.to_hash::<H>().to_bytes();

        match trie::verify_proof_with_hash::<T>(&key, &witness.proofs, trie_root) {
            ProofResult::Exists(record) => Some(record.weight()),
            ProofResult::NotExists => Some(T::Weight::default()),
            ProofResult::Invalid => None,
        }
    }

    pub fn apply_operations<H: Hasher>(&self, trie: &mut Trie<H, T>, witness: &Witness) -> bool {
        trie.apply_operations(
            self.operations.iter().map(|(k, v)| (k, v.clone())),
            Some(&witness.proofs),
        )
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

impl<T: Record> Builder<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_parent_hash(mut self, parent: Multihash) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn with_checkpoint(mut self, checkpoint: Multihash) -> Self {
        self.checkpoint = Some(checkpoint);
        self
    }

    pub fn with_dependencie(mut self, dep: Multihash) -> Self {
        self.dependencies.insert(dep);
        self
    }

    pub fn with_dependencies<I>(mut self, deps: I) -> Self
    where
        I: IntoIterator<Item = Multihash>,
    {
        self.dependencies.extend(deps);
        self
    }

    pub fn with_operation(mut self, key: Vec<u8>, operation: T::Operation) -> Self {
        self.operations.insert(key, operation);
        self
    }

    pub fn with_operations<I>(mut self, ops: I) -> Self
    where
        I: IntoIterator<Item = (Vec<u8>, T::Operation)>,
    {
        self.operations.extend(ops);
        self
    }

    pub fn with_proposer_pk(mut self, pk: PublicKey) -> Self {
        self.proposer_pk = Some(pk);
        self
    }

    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn build(self) -> Option<Proposal<T>> {
        let parent = self.parent?;
        let checkpoint = self.checkpoint?;
        let proposer_pk = self.proposer_pk?;

        Some(Proposal {
            parent,
            checkpoint,
            dependencies: self.dependencies,
            operations: self.operations,
            proposer_pk,
            metadata: self.metadata,
            hash_cache: OnceLock::new(),
        })
    }
}

// #[cfg(test)]
// mod tests {
//     use vdf::{VDFParams, WesolowskiVDFParams};
//
//     use super::*;
//
//     type TestHasher = sha2::Sha256;
//     type Trie = trie::Trie<TestHasher>;
//
//     const TO_WEIGHT: Weight = 200;
//     const VDF_PARAMS: WesolowskiVDFParams = WesolowskiVDFParams(1024);
//     const VDF_DIFFICULTY: u64 = 1;
//
//     fn setup() -> (Proposal, Witness) {
//         let sk = SecretKey::random();
//         let pk = sk.public_key();
//
//         let to_record = Record::new(TO_WEIGHT, vec![4, 5, 6]);
//
//         let proposer = Builder::new()
//             .with_parent_hash(Multihash::default())
//             .with_operation_clcu::<TestHasher>(&sk, None, to_record.clone())
//             .with_proposer_pk(pk.clone())
//             .build()
//             .expect("Proposal should be valid");
//
//         let vdf = VDF_PARAMS.new();
//
//         let witness = proposer
//             .generate_witness::<TestHasher>(&sk, &Trie::empty(), &vdf, VDF_DIFFICULTY)
//             .expect("Witness should be generated successfully");
//
//         (proposer, witness)
//     }
//
//     fn random_signature() -> Signature {
//         let sk = SecretKey::random();
//         let msg = vec![0; 32];
//         sk.sign(&msg)
//     }
//
//     #[test]
//     fn veirfy_signature() {
//         let (prop, witness) = setup();
//
//         let invalid_winess = Witness {
//             sig: random_signature(),
//             ..witness.clone()
//         };
//
//         assert!(prop.verify_signature::<TestHasher>(&witness));
//         assert!(!prop.verify_signature::<TestHasher>(&invalid_winess));
//     }
//
//     #[test]
//     fn verify_vdf() {
//         let (prop, witness) = setup();
//
//         let vdf = VDF_PARAMS.new();
//
//         let invalid_witness = Witness {
//             vdf_proof: vec![0; 32], // Invalid proof
//             ..witness.clone()
//         };
//
//         assert!(prop.verify_vdf::<TestHasher>(&witness, &vdf, VDF_DIFFICULTY));
//         assert!(!prop.verify_vdf::<TestHasher>(&invalid_witness, &vdf, VDF_DIFFICULTY));
//     }
// }
