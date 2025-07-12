use std::collections::BTreeSet;

use crate::traits::serializable::{self, Serializable};

impl<V> Serializable for BTreeSet<V>
where
    V: Serializable + Ord,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let size = usize::from_reader(reader)?;
        let mut set = BTreeSet::new();

        for _ in 0..size {
            let value = V::from_reader(reader)?;
            set.insert(value);
        }

        Ok(set)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);
        self.iter().for_each(|value| {
            value.to_writer(writer);
        });
    }
}
