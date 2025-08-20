use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use civita_serialize::Serialize;
use civita_serialize_derive::Serialize;
use derivative::Derivative;

use crate::crypto::{hasher::Hasher, Multihash, PublicKey, SecretKey, Signature};

pub type Key = Vec<u8>;
pub type Height = u32;
pub type Nonce = u16;

pub trait Command: Clone + Serialize + Send + Sync + Sized + 'static {
    type Value: Clone + Default + Serialize + Send + Sync + Sized + 'static;

    fn keys(&self) -> HashSet<Key>;
    fn execute(
        &self,
        input: HashMap<Key, Self::Value>,
    ) -> Result<HashMap<Key, Self::Value>, String>;
}

#[derive(Clone)]
#[derive(Serialize)]
#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct Atom<C> {
    pub height: Height,
    pub nonce: Nonce,

    pub cmd: Option<C>,

    pub vdf_proof: Vec<u8>,
    pub timestamp: u64,

    #[serialize(skip)]
    cache: OnceLock<Multihash>,
}

#[derive(Clone)]
#[derive(Serialize)]
pub struct Witness {
    pub sig: Signature,
    pub parents: HashMap<PublicKey, Multihash>,
    pub trie_proofs: HashMap<Multihash, Vec<u8>>,
}

impl<C: Serialize> Atom<C> {
    pub fn hash(&self) -> Multihash {
        *self.cache.get_or_init(|| Hasher::digest(&self.to_vec()))
    }
}

impl Default for Witness {
    fn default() -> Self {
        let sk = SecretKey::default();
        let atom = Atom::<Vec<u8>>::default();
        let sig = sk.sign(&atom.hash().to_vec());
        Witness {
            sig,
            parents: HashMap::new(),
            trie_proofs: HashMap::new(),
        }
    }
}
