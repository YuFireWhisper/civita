use crate::traits::{serializable, Serializable};

impl<A, B> Serializable for (A, B)
where
    A: Serializable,
    B: Serializable,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let a = A::from_reader(reader)?;
        let b = B::from_reader(reader)?;
        Ok((a, b))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.0.to_writer(writer);
        self.1.to_writer(writer);
    }
}
