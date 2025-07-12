use libp2p::{multihash::Multihash, PeerId};

use crate::traits::{serializable, Serializable};

impl Serializable for PeerId {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let multihash = Multihash::from_reader(reader)?;
        PeerId::from_multihash(multihash)
            .map_err(|_| serializable::Error("Failed to convert Multihash to PeerId".to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.as_ref().to_writer(writer)
    }
}
