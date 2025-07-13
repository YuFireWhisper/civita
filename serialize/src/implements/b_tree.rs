use std::collections::{BTreeMap, BTreeSet};

use crate::*;

impl<K, V> Serialize for BTreeMap<K, V>
where
    K: Serialize + Ord,
    V: Serialize,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
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
        self.iter().for_each(|(key, value)| {
            key.to_writer(writer);
            value.to_writer(writer);
        });
    }
}

impl<V: Serialize + Ord> Serialize for BTreeSet<V> {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
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
