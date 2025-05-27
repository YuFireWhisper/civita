use serde::{Deserialize, Serialize};

use crate::constants::U32_LENGTH;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid length")]
    InvalidLength,
}

#[derive(Clone)]
#[derive(Debug)]
#[derive(Default)]
#[derive(PartialEq, Eq)]
#[derive(Serialize, Deserialize)]
pub struct Record {
    pub stakes: u32,
    pub data: Vec<u8>,
}

impl Record {
    pub fn new(stakes: u32, data: Vec<u8>) -> Self {
        Record { stakes, data }
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes.to_vec())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.into()
    }
}

impl TryFrom<&[u8]> for Record {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < U32_LENGTH {
            return Err(Error::InvalidLength);
        }

        let stakes = u32::from_le_bytes(
            value[0..U32_LENGTH]
                .try_into()
                .map_err(|_| Error::InvalidLength)?,
        );
        let data = value[U32_LENGTH..].to_vec();

        Ok(Record { stakes, data })
    }
}

impl TryFrom<Vec<u8>> for Record {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        (value.as_slice()).try_into()
    }
}

impl From<&Record> for Vec<u8> {
    fn from(record: &Record) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(U32_LENGTH + record.data.len());
        bytes.extend_from_slice(&record.stakes.to_le_bytes());
        bytes.extend_from_slice(&record.data);
        bytes
    }
}

impl From<Record> for Vec<u8> {
    fn from(record: Record) -> Vec<u8> {
        (&record).into()
    }
}
