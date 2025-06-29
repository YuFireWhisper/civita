use crate::traits::{serializable, ConstantSize, Serializable};

impl<T> Serializable for Vec<T>
where
    T: Serializable + ConstantSize,
{
    fn serialized_size(&self) -> usize {
        usize::SIZE + self.len() * T::SIZE
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let size = usize::from_reader(reader)?;
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(T::from_reader(reader)?);
        }
        Ok(vec)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.len().to_writer(writer)?;
        for item in self {
            item.to_writer(writer)?;
        }
        Ok(())
    }
}
