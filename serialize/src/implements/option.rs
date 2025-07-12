use std::io::{Read, Write};

use crate::*;

impl<T: Serialize> Serialize for Option<T> {
    fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
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
