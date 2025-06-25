use libp2p::{multihash::Multihash, PeerId};

use crate::traits::{serializable, Serializable};

impl Serializable for PeerId {
    fn serialized_size(&self) -> usize {
        self.as_ref().encoded_len()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let multihash = Multihash::read(reader).map_err(|e| serializable::Error(e.to_string()))?;
        PeerId::from_multihash(multihash)
            .map_err(|_| serializable::Error("Failed to create PeerId from multihash".to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.as_ref()
            .write(writer)
            .map_err(|e| serializable::Error(e.to_string()))?;
        Ok(())
    }
}
