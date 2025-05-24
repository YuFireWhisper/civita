use crate::constants::U32_LENGTH;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Invalid length")]
    InvalidLength,
}

pub struct Record {
    pub stakes: u32,
    pub data: Vec<u8>,
}

impl TryFrom<Vec<u8>> for Record {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
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
