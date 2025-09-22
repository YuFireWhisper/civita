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

    #[error("Cannot provide required data: remote needs data before local start")]
    CannotProvideRequiredData,

    #[error("Remote epoch exceeds local end")]
    RemoteEpochExceedsLocalEnd,
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
        remote_last_snapshot: Option<u32>,
        last_epoch_atoms: &[Atom],
        replacement_mmr: Option<Mmr<Token>>,
        remote_len_limit: u32,
        path: &str,
    ) -> Result<()> {
        let local_len = self.snapshot_end - self.start + 1;

        if let Some(remote_number) = remote_last_snapshot {
            if remote_number < self.start && remote_len_limit > local_len {
                return Err(Error::CannotProvideRequiredData);
            }

            if remote_number > self.snapshot_end {
                return Err(Error::RemoteEpochExceedsLocalEnd);
            }

            let min = (self.snapshot_end.saturating_sub(remote_len_limit - 1)).max(self.start);

            if remote_number >= min && remote_number <= self.snapshot_end {
                self.export_incremental(remote_number, last_epoch_atoms, path)?;
                return Ok(());
            }
        }

        if remote_len_limit <= local_len {
            self.export_full_from_start(replacement_mmr, last_epoch_atoms, path)?;
        } else {
            return Err(Error::CannotProvideRequiredData);
        }

        Ok(())
    }

    fn export_full_from_start(
        &self,
        replacement_mmr: Option<Mmr<Token>>,
        last_epoch_atoms: &[Atom],
        path: &str,
    ) -> Result<()> {
        let opt = Options::default();
        let mut sst_writer = SstFileWriter::create(&opt);
        sst_writer.open(path)?;

        self.write_snapshot_to_sst(&mut sst_writer, self.start, replacement_mmr)?;

        for epoch in self.start..self.snapshot_end {
            self.write_epoch_to_sst(&mut sst_writer, epoch)?;
        }

        let atoms_value = Value::Epoch {
            atoms: last_epoch_atoms.to_vec(),
        }
        .to_bytes();
        sst_writer.put(self.snapshot_end.to_be_bytes(), atoms_value)?;

        sst_writer.finish()?;
        Ok(())
    }

    fn export_incremental(
        &self,
        remote_number: u32,
        last_epoch_atoms: &[Atom],
        path: &str,
    ) -> Result<()> {
        let opt = Options::default();
        let mut sst_writer = SstFileWriter::create(&opt);
        sst_writer.open(path)?;

        for epoch in remote_number..self.snapshot_end {
            self.write_epoch_to_sst(&mut sst_writer, epoch)?;
        }

        let atoms_value = Value::Epoch {
            atoms: last_epoch_atoms.to_vec(),
        }
        .to_bytes();
        sst_writer.put(self.snapshot_end.to_be_bytes(), atoms_value)?;

        sst_writer.finish()?;
        Ok(())
    }

    fn write_snapshot_to_sst(
        &self,
        writer: &mut SstFileWriter,
        epoch: u32,
        replacement_mmr: Option<Mmr<Token>>,
    ) -> Result<()> {
        use bincode::{
            config,
            serde::{decode_from_slice, encode_to_vec},
        };

        const KEY: &[u8] = b"snapshot";

        let cf_name = ColumnName::Snapshot.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        let key = epoch.to_be_bytes();
        let value = self.db.get_cf(cf, &key)?.unwrap();

        let Value::Snapshot { difficulty, mmr } = decode_from_slice(&value, config::standard())?.0
        else {
            panic!("Expected a Snapshot value");
        };
        let mmr = replacement_mmr.unwrap_or(mmr);
        let bytes = encode_to_vec((difficulty, mmr), config::standard()).unwrap();

        writer.put(KEY, &bytes)?;

        Ok(())
    }

    fn write_epoch_to_sst(&self, writer: &mut SstFileWriter, epoch: u32) -> Result<()> {
        let cf_name = ColumnName::Epochs.to_string();
        let cf = self.db.cf_handle(&cf_name).unwrap();

        let key = epoch.to_be_bytes();
        if let Some(value) = self.db.get_cf(cf, &key)? {
            writer.put(epoch.to_be_bytes(), &value)?;
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
