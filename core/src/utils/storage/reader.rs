use std::path::Path;

use rocksdb::{IteratorMode, Options, DB};

use crate::{
    ty::{atom::Atom, token::Token},
    utils::{
        mmr::Mmr,
        storage::{self, Storage},
    },
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),

    #[error(transparent)]
    Storage(#[from] storage::Error),

    #[error("No data source available")]
    NoDataSource,

    #[error("Invalid Key format")]
    InvalidKeyFormat,

    #[error("No epochs found in SST")]
    NoEpochsFound,

    #[error("SST has unexpected snapshot presence")]
    SSTUnexpectedSnapshot,

    #[error("SST epoch count mismatch")]
    SSTEpochCountMismatch,

    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),

    #[error("Snapshot not found")]
    NoSnapshotFound,
}

pub struct Reader {
    storage: Option<Storage>,
    sst: Option<DB>,

    cur: u32,
    storage_end: Option<u32>,
    end: u32,
    snap: u32,
    len: u32,
}

impl Reader {
    pub fn new(storage_path: &str, sst_path: Option<&str>, len: u32) -> Result<Self> {
        debug_assert_ne!(len, 0);

        let mut max_epoch;

        let storage = Self::open_storage(storage_path, len)?;
        let storage_end = storage.as_ref().map(|s| s.epoch_end);
        max_epoch = storage_end.unwrap_or(0);

        let sst = if let Some(path) = sst_path {
            let sst = Self::open_sst(path)?;
            max_epoch = Self::validate_sst_data(&sst, storage_end, len)?;
            Some(sst)
        } else {
            None
        };

        if storage.is_none() && sst.is_none() {
            return Err(Error::NoDataSource);
        }

        let start = max_epoch.saturating_sub(len - 1);
        let snap = start;

        Ok(Reader {
            storage,
            sst,
            cur: start,
            storage_end,
            end: max_epoch,
            snap,
            len,
        })
    }

    fn open_storage(path: &str, len: u32) -> Result<Option<Storage>> {
        if Path::new(path).exists() {
            Storage::new(len, path).map(Some).map_err(Error::from)
        } else {
            Ok(None)
        }
    }

    fn open_sst(path: &str) -> Result<DB> {
        let opts = Options::default();
        DB::open(&opts, path).map_err(Error::from)
    }

    fn validate_sst_data(sst: &DB, storage_end: Option<u32>, len: u32) -> Result<u32> {
        let (epochs, has_snapshot) = Self::get_sst_epochs_and_snapshot(sst)?;

        if epochs.is_empty() {
            return Err(Error::NoEpochsFound);
        }

        let max_epoch = *epochs.last().unwrap();
        let exp_start = max_epoch.saturating_sub(len - 1);
        let exp_have_snapshot = storage_end.map_or(true, |end| exp_start > end);

        if exp_have_snapshot != has_snapshot {
            return Err(Error::SSTUnexpectedSnapshot);
        }

        let expected_epoch_count = if exp_have_snapshot {
            len
        } else {
            max_epoch - storage_end.unwrap()
        };

        if epochs.len() as u32 != expected_epoch_count {
            return Err(Error::SSTEpochCountMismatch);
        }

        Ok(max_epoch)
    }

    fn get_sst_epochs_and_snapshot(sst_db: &DB) -> Result<(Vec<u32>, bool)> {
        let mut epochs = Vec::new();
        let mut has_snapshot = false;
        let iter = sst_db.iterator(IteratorMode::Start);

        for item in iter {
            let key = item?.0;
            let bytes = key.as_ref();

            if bytes == b"snapshot" {
                has_snapshot = true;
                continue;
            }

            epochs.push(u32::from_be_bytes(
                bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?,
            ));
        }

        epochs.sort_unstable();
        Ok((epochs, has_snapshot))
    }

    pub fn snapshot(&self) -> Result<(u64, Mmr<Token>)> {
        use bincode::{config, serde::decode_from_std_read};

        if self.storage_end.is_none_or(|end| self.snap > end) {
            let sst = self.sst.as_ref().expect("SST should be available here");
            let key = b"snapshot";
            let value = sst.get(key)?.ok_or(Error::NoSnapshotFound)?;
            let mut bytes: &[u8] = &value;
            let difficulty: u64 = decode_from_std_read(&mut bytes, config::standard())?;
            let mmr: Mmr<Token> = decode_from_std_read(&mut bytes, config::standard())?;
            Ok((difficulty, mmr))
        } else {
            let storage = self
                .storage
                .as_ref()
                .expect("Storage should be available here");
            storage
                .get_snapshot(self.snap)?
                .ok_or(Error::NoSnapshotFound)
        }
    }

    pub fn next(&mut self) -> Result<Option<Vec<Atom>>> {
        use bincode::{config, serde::decode_from_slice};

        if self.cur > self.end {
            return Ok(None);
        }

        let cur = self.cur;
        self.cur += 1;

        if self.storage_end.is_none_or(|end| cur > end) {
            let sst = self.sst.as_ref().expect("SST should be available here");
            let key = cur.to_be_bytes();
            let value = sst.get(&key)?.ok_or(Error::NoEpochsFound)?;
            let atoms: Vec<Atom> = decode_from_slice(&value, config::standard())?.0;
            Ok(Some(atoms))
        } else {
            let storage = self
                .storage
                .as_ref()
                .expect("Storage should be available here");
            let atoms = storage.get_epoch(cur)?.ok_or(Error::NoEpochsFound)?;
            Ok(Some(atoms))
        }
    }
}
