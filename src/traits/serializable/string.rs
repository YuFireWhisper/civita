use crate::traits::{serializable, ConstantSize, Serializable};

impl Serializable for String {
    fn serialized_size(&self) -> usize {
        usize::SIZE + self.len()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let size = usize::from_reader(reader)?;
        let mut buffer = vec![0; size];
        reader.read_exact(&mut buffer)?;
        String::from_utf8(buffer).map_err(|e| serializable::Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.len().to_writer(writer)?;
        writer.write_all(self.as_bytes())?;
        Ok(())
    }
}
