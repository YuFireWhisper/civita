use std::{
    collections::{BTreeSet, HashMap},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;

use crate::crypto::{hasher::Hasher, Multihash};

pub type Key = Vec<u8>;
pub type Height = u32;
pub type Version = u16;

pub trait MergeStrategy<V>: Send + Sync + 'static {
    fn is_mergeable(&self, key: &Key) -> bool;
    fn merge(&self, key: &Key, left: &V, right: &V) -> V;
}

pub trait Command: Clone + Serialize + Send + Sync + Sized + 'static {
    type Value: Clone + Default + Serialize + Send + Sync + Sized + 'static;

    fn input(&self) -> HashMap<Key, Option<Version>>;
    fn output(&self, input: HashMap<Key, Self::Value>)
        -> Result<HashMap<Key, Self::Value>, String>;
}

#[derive(Serialize)]
pub struct Atom<C> {
    pub height: Height,

    pub cmd: Option<C>,

    pub timestamp: u64,
    pub vdf_proof: Vec<u8>,

    pub atoms: BTreeSet<Multihash>,

    #[serialize(skip)]
    cache: OnceLock<Multihash>,
}

pub struct Witness {
    pub trie_proofs: HashMap<Multihash, Vec<u8>>,
}

impl<C: Serialize> Atom<C> {
    pub fn hash(&self) -> Multihash {
        *self.cache.get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}
