pub mod implements;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct Error(pub String);

pub trait Serialize: Sized {
    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, Error>;
    fn to_writer<W: std::io::Write>(&self, writer: &mut W);
    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let mut reader = slice;
        Self::from_reader(&mut reader)
    }
    fn to_vec(&self) -> Vec<u8> {
        let mut writer = Vec::new();
        self.to_writer(&mut writer);
        writer
    }
}

impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}
