use crate::*;

impl<T> Serialize for Vec<T>
where
    T: Serialize,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let size = usize::from_reader(reader)?;
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(T::from_reader(reader)?);
        }
        Ok(vec)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.len().to_writer(writer);
        for item in self {
            item.to_writer(writer);
        }
    }
}
