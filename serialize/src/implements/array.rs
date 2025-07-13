use crate::*;

impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let mut vec = Vec::with_capacity(N);

        for _ in 0..N {
            let item = T::from_reader(reader)?;
            vec.push(item);
        }

        let array: [T; N] = match vec.try_into() {
            Ok(array) => array,
            Err(vec) => {
                panic!(
                    "Failed to convert Vec<T> to [T; N]. Expected length: {}, got: {}",
                    N,
                    vec.len()
                )
            }
        };

        Ok(array)
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) {
        for item in self {
            item.to_writer(writer);
        }
    }
}
