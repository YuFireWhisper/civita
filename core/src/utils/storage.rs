use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, SstFileWriter, DB};
use serde::{Deserialize, Serialize};

use crate::{
    ty::{atom::Atom, token::Token},
    utils::mmr::Mmr,
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

    #[error("No epochs found")]
    NoEpochsFound,

    #[error("Range out of bounds: start {start} < min known {min_known} or end {end} > max known {max_known}")]
    RangeOutOfBounds {
        start: u32,
        end: u32,
        min_known: u32,
        max_known: u32,
    },
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

pub struct Storage(DB);

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
}

impl Storage {
    pub fn new(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let s_cf = ColumnFamilyDescriptor::new(ColumnName::Snapshot, Options::default());
        let e_cf = ColumnFamilyDescriptor::new(ColumnName::Epochs, Options::default());

        DB::open_cf_descriptors(&opts, path, vec![s_cf, e_cf])
            .map(Storage)
            .map_err(Error::from)
    }

    pub fn put(&self, key: Key, value: Value) -> Result<()> {
        let cf_name = key.to_column().to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");

        self.0
            .put_cf(cf, key.epoch().to_be_bytes(), value.to_bytes())?;

        Ok(())
    }

    pub fn prune(&self, len: u32) -> Result<()> {
        let mut epochs = self.get_all_epochs()?;
        epochs.sort_unstable();

        let to_delete = &epochs[..epochs.len() - len as usize];
        for epoch in to_delete {
            self.delete_epoch(*epoch)?;
            self.delete_snapshot(*epoch)?;
        }

        Ok(())
    }

    fn get_all_epochs(&self) -> Result<Vec<u32>> {
        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");

        let mut epochs = Vec::new();
        let iter = self.0.iterator_cf(cf, IteratorMode::Start);

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

    fn delete_snapshot(&self, epoch: u32) -> Result<()> {
        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");
        self.0.delete_cf(cf, epoch.to_be_bytes())?;
        Ok(())
    }

    fn delete_epoch(&self, epoch: u32) -> Result<()> {
        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");
        self.0.delete_cf(cf, epoch.to_be_bytes())?;
        Ok(())
    }

    pub fn export_to_sst<P: AsRef<Path>>(
        &self,
        start: u32,
        end: u32,
        strict: bool,
        path: P,
    ) -> Result<()> {
        let mut known_epochs = self.get_all_epochs()?;

        if known_epochs.is_empty() {
            return Err(Error::NoEpochsFound);
        }

        known_epochs.sort_unstable();
        let min_known = *known_epochs.first().unwrap();
        let max_known = *known_epochs.last().unwrap();

        let (actual_start, actual_end) = if strict {
            if start < min_known || end > max_known {
                return Err(Error::RangeOutOfBounds {
                    start,
                    end,
                    min_known,
                    max_known,
                });
            }
            (start, end)
        } else {
            let actual_start = start.max(min_known);
            let actual_end = end.min(max_known);
            (actual_start, actual_end)
        };

        let path_str = path.as_ref().to_string_lossy().to_string();
        let opt = Options::default();
        let mut sst_writer = SstFileWriter::create(&opt);
        sst_writer.open(&path_str)?;

        self.write_first_snapshot_to_sst(&mut sst_writer, actual_start)?;
        self.write_epochs_to_sst(&mut sst_writer, actual_start, actual_end)?;

        sst_writer.finish()?;

        Ok(())
    }

    fn write_first_snapshot_to_sst(
        &self,
        sst_writer: &mut SstFileWriter,
        first_epoch: u32,
    ) -> Result<()> {
        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");

        let key = first_epoch.to_be_bytes();
        let value = self.0.get_cf(cf, &key)?.expect("First snapshot must exist");
        let key = Key::Snapshot(first_epoch);
        sst_writer.put(key.to_bytes(), &value)?;

        Ok(())
    }

    fn write_epochs_to_sst(
        &self,
        sst_writer: &mut SstFileWriter,
        start: u32,
        end: u32,
    ) -> Result<()> {
        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.0.cf_handle(&cf_name).expect("Column family not found");

        for epoch in start..=end {
            let key = epoch.to_be_bytes();
            let value = self.0.get_cf(cf, &key)?.expect("Epoch must exist");
            let key = Key::Epoch(epoch);
            sst_writer.put(key.to_bytes(), &value)?;
        }

        Ok(())
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
