use crate::*;

impl<T: Serialize> Serialize for Box<T> {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let inner = T::from_reader(reader)?;
        Ok(Box::new(inner))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.as_ref().to_writer(writer)
    }
}
