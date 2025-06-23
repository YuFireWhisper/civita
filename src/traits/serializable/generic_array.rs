use generic_array::{ArrayLength, GenericArray};

use crate::traits::serializable::{self, ConstantSize, Serializable};

impl<N> Serializable for GenericArray<u8, N>
where
    N: ArrayLength,
{
    fn serialized_size(&self) -> usize {
        N::to_usize()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let mut array = GenericArray::default();
        reader.read_exact(array.as_mut_slice())?;
        Ok(array)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        writer.write_all(self.as_slice())?;
        Ok(())
    }
}

impl<N> ConstantSize for GenericArray<u8, N>
where
    N: ArrayLength,
{
    const SIZE: usize = N::USIZE;
}
