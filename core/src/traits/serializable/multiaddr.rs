use libp2p::Multiaddr;

use crate::traits::{serializable, Serializable};

impl Serializable for Multiaddr {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let size = usize::from_reader(reader)?;

        let mut bytes = vec![0; size];
        reader.read_exact(&mut bytes)?;

        Multiaddr::try_from(bytes).map_err(|e| serializable::Error(e.to_string()))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        let bytes = self.to_vec();
        let size = bytes.len();

        size.to_writer(writer);
        writer
            .write_all(&bytes)
            .expect("Failed to write Multiaddr bytes");
    }
}
