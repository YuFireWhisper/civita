#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid length")]
    InvalidLength,
}

pub struct ResidentRecord {
    pub stakes: u32,
    pub data: Vec<u8>,
}

impl TryFrom<Vec<u8>> for ResidentRecord {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(Error::InvalidLength);
        }

        let stakes = u32::from_le_bytes(value[0..4].try_into().map_err(|_| Error::InvalidLength)?);
        let data = value[4..].to_vec();

        Ok(ResidentRecord { stakes, data })
    }
}
