use std::{
    collections::HashMap,
    hash::Hash,
    io::{Read, Write},
};

use crate::traits::serializable::{ConstantSize, Error, Serializable};

impl<K, V> Serializable for HashMap<K, V>
where
    K: Serializable + Eq + Hash,
    V: Serializable,
{
    fn serialized_size(&self) -> usize {
        usize::SIZE
            + self
                .iter()
                .map(|(k, v)| k.serialized_size() + v.serialized_size())
                .sum::<usize>()
    }

    fn from_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let size = usize::from_reader(reader)?;

        let mut map = HashMap::with_capacity(size);

        for _ in 0..size {
            let key = K::from_reader(reader)?;
            let value = V::from_reader(reader)?;
            map.insert(key, value);
        }

        Ok(map)
    }

    fn to_writer<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.len().to_writer(writer)?;

        for (key, value) in self {
            key.to_writer(writer)?;
            value.to_writer(writer)?;
        }

        Ok(())
    }
}
