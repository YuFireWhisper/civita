use libp2p::gossipsub::MessageId;

use crate::traits::{serializable, Serializable};

impl Serializable for MessageId {
    fn serialized_size(&self) -> usize {
        self.0.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(MessageId(Vec::<u8>::from_reader(reader)?))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.0.to_writer(writer)
    }
}
