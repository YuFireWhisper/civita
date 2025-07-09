use crate::traits::{serializable, ConstantSize, Serializable};

impl<A, B> Serializable for (A, B)
where
    A: Serializable,
    B: Serializable,
{
    fn serialized_size(&self) -> usize {
        self.0.serialized_size() + self.1.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let a = A::from_reader(reader)?;
        let b = B::from_reader(reader)?;
        Ok((a, b))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.0.to_writer(writer)?;
        self.1.to_writer(writer)?;
        Ok(())
    }
}

impl<A, B> ConstantSize for (A, B)
where
    A: ConstantSize,
    B: ConstantSize,
{
    const SIZE: usize = A::SIZE + B::SIZE;
}
