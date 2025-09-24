use std::sync::atomic::{AtomicU32, Ordering};

use bincode::error::DecodeError;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, DB};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::Multihash,
    ty::{atom::Atom, snapshot::Snapshot, token::Token},
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),

    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Invalid Key format")]
    InvalidKeyFormat,

    #[error("Value {0} is out of range [{1}, {2}]")]
    OutOfRange(u32, u32, u32),
}

#[derive(Clone, Copy)]
enum ColumnName {
    Snapshot,
    Epochs,
    Mmr,
}

#[derive(Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub enum Key {
    Snapshot(u32),
    Epoch(u32),
}

#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub enum MmrValue {
    Internal(u64, Multihash, Multihash),
    Leaf(Token),
}

pub struct Storage {
    db: DB,
    start: AtomicU32,
    end: AtomicU32,
    len: u32,
}

impl Key {
    pub fn to_column(&self) -> ColumnName {
        match self {
            Key::Snapshot(_) => ColumnName::Snapshot,
            Key::Epoch(_) => ColumnName::Epochs,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_to_vec};
        encode_to_vec(self, config::standard()).expect("Failed to serialize key")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        use bincode::{config, serde::decode_from_slice};
        Ok(decode_from_slice(bytes, config::standard())?.0)
    }

    pub fn epoch(&self) -> u32 {
        match self {
            Key::Snapshot(epoch) => *epoch,
            Key::Epoch(epoch) => *epoch,
        }
    }
}

impl MmrValue {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).map(|(s, _)| s)
    }

    pub fn hash(&self) -> Multihash {
        unimplemented!()
    }

    pub fn to_hash_data(&self) -> Vec<u8> {
        use bincode::{
            config,
            serde::{encode_into_std_write, encode_to_vec},
        };

        match self {
            Self::Internal(idx, l, r) => {
                let mut buf = Vec::new();
                encode_into_std_write(idx, &mut buf, config::standard()).unwrap();
                encode_into_std_write(l, &mut buf, config::standard()).unwrap();
                encode_into_std_write(r, &mut buf, config::standard()).unwrap();
                buf
            }
            Self::Leaf(token) => encode_to_vec(token, config::standard()).unwrap(),
        }
    }
}

impl Storage {
    pub fn new(len: u32, path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let s_cf = ColumnFamilyDescriptor::new(ColumnName::Snapshot, Options::default());
        let e_cf = ColumnFamilyDescriptor::new(ColumnName::Epochs, Options::default());

        let db = DB::open_cf_descriptors(&opts, path, vec![s_cf, e_cf])?;

        let storage = Storage {
            db,
            start: AtomicU32::new(0),
            end: AtomicU32::new(0),
            len,
        };

        storage.prune_and_set_bound()?;

        Ok(storage)
    }

    fn prune_and_set_bound(&self) -> Result<()> {
        let mut snaps = self.get_all_numbers(ColumnName::Snapshot)?;
        snaps.sort_by(|a, b| b.cmp(a));

        while snaps.len() > self.len as usize {
            let epoch = snaps.pop().unwrap();
            self.delete_cf(ColumnName::Snapshot, epoch)?;
            self.delete_cf(ColumnName::Epochs, epoch)?;
        }

        self.start.store(*snaps.last().unwrap(), Ordering::Relaxed);
        self.end.store(*snaps.first().unwrap(), Ordering::Relaxed);

        Ok(())
    }

    fn get_all_numbers(&self, name: ColumnName) -> Result<Vec<u32>> {
        let cf_name = name.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        let mut epochs = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);

        for item in iter {
            let (bytes, _) = item?;
            let arr: [u8; 4] = bytes
                .as_ref()
                .try_into()
                .map_err(|_| Error::InvalidKeyFormat)?;
            epochs.push(u32::from_be_bytes(arr));
        }

        Ok(epochs)
    }

    fn delete_cf(&self, name: ColumnName, epoch: u32) -> Result<()> {
        let cf = self.db.cf_handle(&name.to_string()).unwrap();
        self.db.delete_cf(cf, epoch.to_be_bytes())?;
        Ok(())
    }

    pub fn put_snapshot(&self, epoch: u32, snapshot: &Snapshot) -> Result<()> {
        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();
        let value = snapshot.to_bytes();

        self.db.put_cf(cf, key, value)?;
        self.prune_and_set_bound()?;

        Ok(())
    }

    pub fn put_epoch(&self, epoch: u32, atoms: &[Atom]) -> Result<()> {
        use bincode::{config, serde::encode_to_vec};

        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();
        let value = encode_to_vec(atoms, config::standard()).unwrap();

        self.db.put_cf(cf, key, value)?;

        Ok(())
    }

    pub fn put_mmr(&self, hash: &Multihash, value: &MmrValue) -> Result<()> {
        let cf_name = ColumnName::Mmr.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = hash.to_bytes();
        let value = value.to_bytes();

        self.db.put_cf(cf, key, value)?;

        Ok(())
    }

    pub fn get_snapshot(&self, epoch: u32) -> Result<Option<Snapshot>> {
        if epoch < self.start() || epoch > self.end() {
            return Err(Error::OutOfRange(epoch, self.start(), self.end()));
        }

        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();

        if let Some(value) = self.db.get_cf(cf, &key)? {
            Snapshot::from_bytes(&value).map(Some).map_err(Error::from)
        } else {
            Ok(None)
        }
    }

    pub fn get_epoch(&self, epoch: u32) -> Result<Option<Vec<Atom>>> {
        use bincode::{config, serde::decode_from_slice};

        if epoch < self.start() || epoch > self.end() {
            return Err(Error::OutOfRange(epoch, self.start(), self.end()));
        }

        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();

        if let Some(value) = self.db.get_cf(cf, &key)? {
            decode_from_slice(&value, config::standard())
                .map(|(res, _)| Some(res))
                .map_err(Error::from)
        } else {
            Ok(None)
        }
    }

    pub fn get_mmr(&self, hash: &Multihash) -> Result<Option<MmrValue>> {
        let cf_name = ColumnName::Mmr.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = hash.to_bytes();

        if let Some(value) = self.db.get_cf(cf, &key)? {
            MmrValue::from_bytes(&value).map(Some).map_err(Error::from)
        } else {
            Ok(None)
        }
    }

    pub fn contains_snapshot(&self, epoch: u32) -> Result<bool> {
        if epoch < self.start() || epoch > self.end() {
            return Err(Error::OutOfRange(epoch, self.start(), self.end()));
        }

        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();

        Ok(self.db.get_pinned_cf(cf, key)?.is_some())
    }

    pub fn contains_epoch(&self, epoch: u32) -> Result<bool> {
        if epoch < self.start() || epoch > self.end() {
            return Err(Error::OutOfRange(epoch, self.start(), self.end()));
        }

        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = epoch.to_be_bytes();

        Ok(self.db.get_pinned_cf(cf, key)?.is_some())
    }

    pub fn contains_mmr(&self, hash: &Multihash) -> Result<bool> {
        let cf_name = ColumnName::Mmr.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();
        let key = hash.to_bytes();

        Ok(self.db.get_pinned_cf(cf, key)?.is_some())
    }

    pub fn start(&self) -> u32 {
        self.start.load(Ordering::Relaxed)
    }

    pub fn end(&self) -> u32 {
        self.end.load(Ordering::Relaxed)
    }
}

impl ToString for ColumnName {
    fn to_string(&self) -> String {
        match self {
            ColumnName::Snapshot => "snapshot".to_string(),
            ColumnName::Epochs => "epochs".to_string(),
            ColumnName::Mmr => "mmr".to_string(),
        }
    }
}

impl From<ColumnName> for String {
    fn from(col: ColumnName) -> Self {
        col.to_string()
    }
}
