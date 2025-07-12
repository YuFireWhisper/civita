use std::io::{Read, Write};

use crate::traits::serializable::{ConstantSize, Error, Serializable};

impl<T> Serializable for Option<T>
where
    T: Serializable,
{
    fn serialized_size(&self) -> usize {
        1 + match self {
            Some(value) => value.serialized_size(),
            None => 0,
        }
    }

    fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        match u8::from_reader(reader)? {
            1 => Ok(Some(T::from_reader(reader)?)),
            0 => Ok(None),
            i => Err(Error(format!("Unknown option flag: {i}"))),
        }
    }

    fn to_writer<W: Write>(&self, writer: &mut W) {
        match self {
            Some(value) => {
                1u8.to_writer(writer);
                value.to_writer(writer);
            }
            None => 0u8.to_writer(writer),
        }
    }
}

impl<T> ConstantSize for Option<T>
where
    T: ConstantSize,
{
    const SIZE: usize = 1 + T::SIZE;
}
