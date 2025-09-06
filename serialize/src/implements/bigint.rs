use crate::*;

impl Serialize for num_bigint::BigUint {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let vec = Vec::<u8>::from_reader(reader)?;
        Ok(num_bigint::BigUint::from_bytes_be(&vec))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.to_bytes_be().to_writer(writer);
    }
}
