use libp2p::{multihash::Multihash, PeerId};

use crate::*;

impl<const N: usize> Serialize for Multihash<N> {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let code = u64::from_reader(reader)?;
        let size = u8::from_reader(reader)?;

        let mut digest = vec![0; size as usize];
        reader.read_exact(&mut digest)?;

        Multihash::wrap(code, &digest).map_err(|e| Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.code().to_writer(writer);
        self.size().to_writer(writer);
        writer
            .write_all(self.digest())
            .expect("Failed to write digest");
    }
}

impl Serialize for PeerId {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let multihash = Multihash::from_reader(reader)?;
        PeerId::from_multihash(multihash)
            .map_err(|_| Error("Failed to convert Multihash to PeerId".to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.as_ref().to_writer(writer)
    }
}
