use std::io::{Read, Write};

use crate::*;

macro_rules! impl_serialize_for_numeric {
    ($($type:ty),*) => {
        $(
            impl Serialize for $type {
                fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
                    let mut buffer = [0u8; size_of::<$type>()];
                    reader.read_exact(&mut buffer)?;
                    Ok(<$type>::from_ne_bytes(buffer))
                }

                fn to_writer<W: Write>(&self, writer: &mut W) {
                    writer.write_all(&self.to_ne_bytes()).expect("Failed to write numeric value");
                }
            }
        )*
    };
}

impl_serialize_for_numeric!(
    i8, i16, i32, i64, i128, u8, u16, u32, u64, u128, usize, isize, f32, f64
);
