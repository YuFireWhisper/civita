use crate::*;

impl Serialize for String {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let size = usize::from_reader(reader)?;
        let mut buffer = vec![0; size];
        reader.read_exact(&mut buffer)?;
        String::from_utf8(buffer).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);
        writer
            .write_all(self.as_bytes())
            .expect("Failed to write string");
    }
}
