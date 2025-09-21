use std::path::Path;

use rocksdb::{IteratorMode, Options, DB};

use crate::{
    ty::{atom::Atom, token::Token},
    utils::{
        mmr::Mmr,
        storage::{Key, Value},
    },
};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),

    #[error("Invalid Key format")]
    InvalidKeyFormat,

    #[error("No snapshot found")]
    NoSnapshotFound,

    #[error("No epochs found")]
    NoEpochsFound,

    #[error("Expected got snapshot, but found epoch")]
    ExpectedSnapshot,

    #[error("Expected got epoch, but found snapshot")]
    ExpectedEpoch,

    #[error("SST file not found")]
    SstFileNotFound,

    #[error("End of SST file reached")]
    EndOfFile,

    #[error(transparent)]
    Decode(#[from] bincode::error::DecodeError),
}

pub struct SstReader {
    db: DB,
    start_epoch: u32,
    current_epoch: u32,
    max_epoch: u32,
}

impl SstReader {
    pub fn new<P: AsRef<Path>>(sst_path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);

        let db = DB::open(&opts, sst_path.as_ref())?;
        let epochs = Self::load_epochs(&db)?;
        let start_epoch = *epochs.first().unwrap();

        Ok(SstReader {
            db,
            start_epoch,
            current_epoch: start_epoch,
            max_epoch: *epochs.last().unwrap(),
        })
    }

    fn load_epochs(db: &DB) -> Result<Vec<u32>> {
        let mut epochs = Vec::new();

        let iter = db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            let key = Key::from_bytes(&key).map_err(|_| Error::InvalidKeyFormat)?;
            epochs.push(key.epoch());
        }

        if epochs.is_empty() {
            return Err(Error::NoEpochsFound);
        }

        epochs.sort_unstable();

        Ok(epochs)
    }

    pub fn snapshot(&self) -> Result<(u64, Mmr<Token>)> {
        let key = Key::Snapshot(self.start_epoch).to_bytes();
        let value = self.db.get(&key)?.ok_or(Error::NoSnapshotFound)?;
        let value = Value::from_bytes(&value)?;

        if let Value::Snapshot { mmr, difficulty } = value {
            Ok((difficulty, mmr))
        } else {
            Err(Error::ExpectedSnapshot)
        }
    }

    pub fn next(&mut self) -> Result<Option<Vec<Atom>>> {
        if self.current_epoch > self.max_epoch {
            return Ok(None);
        }

        let key = Key::Epoch(self.current_epoch).to_bytes();
        let value = self.db.get(&key)?.ok_or(Error::NoEpochsFound)?;
        let value = Value::from_bytes(&value)?;

        if let Value::Epoch { atoms } = value {
            self.current_epoch += 1;
            Ok(Some(atoms))
        } else {
            Err(Error::ExpectedEpoch)
        }
    }

    pub fn reset(&mut self) {
        self.current_epoch = self.start_epoch;
    }

    pub fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    pub fn has_more(&self) -> bool {
        self.current_epoch <= self.max_epoch
    }
}
