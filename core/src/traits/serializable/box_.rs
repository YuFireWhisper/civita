use crate::traits::{serializable, Serializable};

impl<T> Serializable for Box<T>
where
    T: Serializable,
{
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        let inner = T::from_reader(reader)?;
        Ok(Box::new(inner))
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        self.as_ref().to_writer(writer)
    }
}
