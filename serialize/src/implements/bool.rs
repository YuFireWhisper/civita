use crate::*;

impl Serialize for bool {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let byte = u8::from_reader(reader)?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error("Invalid boolean value".to_string())),
        }
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        let byte = if *self { 1 } else { 0 };
        byte.to_writer(writer);
    }
}

