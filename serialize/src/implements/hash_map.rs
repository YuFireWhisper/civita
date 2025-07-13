use std::{
    collections::HashMap,
    hash::Hash,
    io::{Read, Write},
};

use crate::*;

impl<K, V> Serialize for HashMap<K, V>
where
    K: Serialize + Eq + Hash,
    V: Serialize,
{
    fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let size = usize::from_reader(reader)?;
        let mut map = HashMap::with_capacity(size);

        for _ in 0..size {
            let key = K::from_reader(reader)?;
            let value = V::from_reader(reader)?;
            map.insert(key, value);
        }

        Ok(map)
    }

    fn to_writer<W: Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);
        self.iter().for_each(|(key, value)| {
            key.to_writer(writer);
            value.to_writer(writer);
        });
    }
}
