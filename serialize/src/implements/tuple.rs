use crate::*;

impl<T, U> Serialize for (T, U)
where
    T: Serialize,
    U: Serialize,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let first = T::from_reader(reader)?;
        let second = U::from_reader(reader)?;
        Ok((first, second))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.0.to_writer(writer);
        self.1.to_writer(writer);
    }
}
