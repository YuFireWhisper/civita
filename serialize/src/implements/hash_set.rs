use std::{collections::HashSet, hash::Hash};

use crate::*;

impl<T: Serialize + Eq + Hash> Serialize for HashSet<T> {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let len = u64::from_reader(reader)?;
        let mut set = HashSet::new();
        for _ in 0..len {
            let item = T::from_reader(reader)?;
            set.insert(item);
        }
        Ok(set)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);
        self.iter().for_each(|item| {
            item.to_writer(writer);
        });
    }
}
