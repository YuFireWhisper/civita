use bincode::error::DecodeError;
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, SstFileWriter, DB};
use serde::{Deserialize, Serialize};

use crate::{
    ty::{atom::Atom, token::Token},
    utils::mmr::Mmr,
};

mod sst_reader;

pub use sst_reader::SstReader;

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

    #[error("No epochs found")]
    NoEpochsFound,

    #[error("Snapshots are not strictly increasing")]
    NonStrictlyIncreasingNumbers,

    #[error("Invalid Count Relation between Snapshots and Epochs")]
    InvalidCountRelation,

    #[error("Attempting to put non-strictly increasing epoch")]
    NonStrictlyIncreasingPut,

    #[error("Export epoch exceeds current snapshot end")]
    ExportEpochExceedsSnapshotEnd,
}

#[derive(Clone, Copy)]
enum ColumnName {
    Snapshot,
    Epochs,
}

#[derive(Clone, Copy)]
#[derive(Serialize, Deserialize)]
pub enum Key {
    Snapshot(u32),
    Epoch(u32),
}

#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub enum Value {
    Snapshot { difficulty: u64, mmr: Mmr<Token> },
    Epoch { atoms: Vec<Atom> },
}

pub struct Storage {
    db: DB,

    start: u32,
    snapshot_end: u32,
    epoch_end: u32,

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

impl Value {
    pub fn to_bytes(&self) -> Vec<u8> {
        use bincode::{config, serde::encode_to_vec};
        encode_to_vec(self, config::standard()).expect("Failed to serialize value")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        use bincode::{config, serde::decode_from_slice};
        Ok(decode_from_slice(bytes, config::standard())?.0)
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

        let mut storage = Storage {
            db,
            start: 0,
            snapshot_end: 0,
            epoch_end: 0,
            len,
        };

        storage.initialize_bounds()?;

        Ok(storage)
    }

    fn initialize_bounds(&mut self) -> Result<()> {
        let snapshots = self.get_all_numbers(ColumnName::Snapshot)?;
        let epochs = self.get_all_numbers(ColumnName::Epochs)?;

        if snapshots.is_empty() && epochs.is_empty() {
            return Ok(());
        }

        if !snapshots.windows(2).all(|w| w[0] < w[1]) || !epochs.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::NonStrictlyIncreasingNumbers);
        }

        if snapshots.len() != epochs.len() && snapshots.len() + 1 != epochs.len() {
            return Err(Error::InvalidCountRelation);
        }

        self.start = *snapshots.first().unwrap();
        self.snapshot_end = *snapshots.last().unwrap();
        self.epoch_end = *epochs.last().unwrap();

        if self.snapshot_end - self.start + 1 > self.len {
            self.prune()?;
        }

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

        epochs.sort_unstable();
        Ok(epochs)
    }

    fn prune(&mut self) -> Result<()> {
        let total = self.snapshot_end - self.start + 1;

        if total < self.len {
            return Ok(());
        }

        let end = self.start + total - self.len;

        for epoch in self.start..end {
            self.delete_cf(ColumnName::Snapshot, epoch)?;
            self.delete_cf(ColumnName::Epochs, epoch)?;
        }

        self.start = end;

        Ok(())
    }

    fn delete_cf(&self, name: ColumnName, epoch: u32) -> Result<()> {
        let cf = self.db.cf_handle(&name.to_string()).unwrap();
        self.db.delete_cf(cf, epoch.to_be_bytes())?;
        Ok(())
    }

    pub fn put(&mut self, key: Key, value: Value) -> Result<()> {
        let epoch = key.epoch();

        match key {
            Key::Snapshot(_) => {
                if epoch != self.snapshot_end + 1 || epoch.abs_diff(self.epoch_end) > 1 {
                    return Err(Error::NonStrictlyIncreasingPut);
                }
            }
            Key::Epoch(_) => {
                if epoch != self.epoch_end + 1 || epoch > self.snapshot_end {
                    return Err(Error::NonStrictlyIncreasingPut);
                }
            }
        }

        let cf_name = key.to_column().to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        self.db.put_cf(cf, epoch.to_be_bytes(), value.to_bytes())?;

        match key {
            Key::Snapshot(_) => self.snapshot_end = epoch,
            Key::Epoch(_) => self.epoch_end = epoch,
        }

        if self.snapshot_end - self.start + 1 > self.len {
            self.prune()?;
        }

        Ok(())
    }

    pub fn export_to_sst(
        &self,
        epoch: u32,
        atoms: Vec<Atom>,
        mmr: Option<Mmr<Token>>,
        path: &str,
    ) -> Result<()> {
        if epoch > self.snapshot_end {
            return Err(Error::ExportEpochExceedsSnapshotEnd);
        }

        let start = self.start.max(epoch);

        let opt = Options::default();
        let mut sst_writer = SstFileWriter::create(&opt);
        sst_writer.open(&path)?;

        self.write_first_snapshot_to_sst(&mut sst_writer, start, mmr)?;
        self.write_epochs_to_sst(&mut sst_writer, start)?;

        let key = Key::Epoch(self.snapshot_end).to_bytes();
        let value = Value::Epoch { atoms }.to_bytes();
        sst_writer.put(key, value)?;

        sst_writer.finish()?;

        Ok(())
    }

    fn write_first_snapshot_to_sst(
        &self,
        writer: &mut SstFileWriter,
        epoch: u32,
        replacement_mmr: Option<Mmr<Token>>,
    ) -> Result<()> {
        use bincode::{config, serde::decode_from_slice};

        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        let key = epoch.to_be_bytes();
        let value = self.db.get_cf(cf, &key)?.unwrap();
        let mut value: Value = decode_from_slice(&value, config::standard())?.0;

        if let Some(mmr) = replacement_mmr {
            if let Value::Snapshot { mmr: ori, .. } = &mut value {
                *ori = mmr;
            } else {
                panic!("Expected a Snapshot value");
            }
        }

        let key = Key::Snapshot(epoch);
        writer.put(key.to_bytes(), value.to_bytes())?;

        Ok(())
    }

    fn write_epochs_to_sst(&self, sst_writer: &mut SstFileWriter, start: u32) -> Result<()> {
        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        for epoch in start..=self.epoch_end {
            let key = epoch.to_be_bytes();
            if let Some(value) = self.db.get_cf(cf, &key)? {
                let key = Key::Epoch(epoch);
                sst_writer.put(key.to_bytes(), &value)?;
            }
        }

        Ok(())
    }

    pub fn current_number(&self) -> u32 {
        self.snapshot_end
    }
}

impl ToString for ColumnName {
    fn to_string(&self) -> String {
        match self {
            ColumnName::Snapshot => "snapshot".to_string(),
            ColumnName::Epochs => "epochs".to_string(),
        }
    }
}

impl From<ColumnName> for String {
    fn from(col: ColumnName) -> Self {
        col.to_string()
    }
}
