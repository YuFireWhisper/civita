use std::collections::BTreeMap;

use crate::traits::{serializable, Serializable};

impl<K, V> Serializable for BTreeMap<K, V>
where
    K: Serializable + Ord,
    V: Serializable,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let size = usize::from_reader(reader)?;
        let mut map = BTreeMap::new();

        for _ in 0..size {
            let key = K::from_reader(reader)?;
            let value = V::from_reader(reader)?;
            map.insert(key, value);
        }

        Ok(map)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);

        for (key, value) in self {
            key.to_writer(writer);
            value.to_writer(writer);
        }
    }
}
