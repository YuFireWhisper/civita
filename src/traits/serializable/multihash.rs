use libp2p::multihash;

use crate::{
    crypto::traits::hasher::Multihash,
    traits::{serializable, ConstantSize, Serializable},
};

impl Serializable for Multihash {
    fn serialized_size(&self) -> usize {
        u64::SIZE + u8::SIZE + self.digest().len()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let code = u64::from_reader(reader)?;
        let size = u8::from_reader(reader)?;

        let mut digest = vec![0; size as usize];
        reader.read_exact(&mut digest)?;

        Ok(Multihash::wrap(code, &digest)?)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.code().to_writer(writer)?;
        self.size().to_writer(writer)?;
        writer.write_all(self.digest())?;
        Ok(())
    }
}

impl From<multihash::Error> for serializable::Error {
    fn from(e: multihash::Error) -> Self {
        serializable::Error(e.to_string())
    }
}
