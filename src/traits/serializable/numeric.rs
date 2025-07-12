use std::io::{Read, Write};

use crate::traits::serializable::{ConstantSize, Error, Serializable};

macro_rules! impl_serializable_for_numeric {
    ($($type:ty),*) => {
        $(
            impl Serializable for $type {
                fn serialized_size(&self) -> usize {
                    size_of::<$type>()
                }

                fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
                    let mut buffer = [0u8; size_of::<$type>()];
                    reader.read_exact(&mut buffer)?;
                    Ok(<$type>::from_ne_bytes(buffer))
                }

                fn to_writer<W: Write>(&self, writer: &mut W) {
                    writer.write_all(&self.to_ne_bytes()).expect("Failed to write numeric value");
                }
            }

            impl ConstantSize for $type {
                const SIZE: usize = size_of::<$type>();
            }
        )*
    };
}

impl_serializable_for_numeric!(
    i8, i16, i32, i64, i128, u8, u16, u32, u64, u128, usize, isize, f32, f64
);
