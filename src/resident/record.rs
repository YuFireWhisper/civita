use serde::{Deserialize, Serialize};

use crate::traits::{serializable, ConstantSize, Serializable};

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
}

impl Serializable for Record {
    fn serialized_size(&self) -> usize {
        u32::SIZE + usize::SIZE + self.data.len()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let stakes = u32::from_reader(reader)?;
        let data_length = usize::from_reader(reader)?;

        let mut data = vec![0; data_length];
        reader.read_exact(&mut data)?;

        Ok(Record { stakes, data })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.stakes.to_writer(writer)?;
        self.data.len().to_writer(writer)?;
        writer.write_all(&self.data)?;
        Ok(())
    }
}
