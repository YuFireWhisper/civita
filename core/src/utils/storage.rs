type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {}

pub trait Storage {
    fn put<K, V>(&self, key: K, value: V) -> Result<()>;
    fn put_with_dir<K, V>(&self, dir: K, key: K, value: V) -> Result<()>;
    fn get<K>(&self, key: K) -> Result<Option<Vec<u8>>>;
    fn get_with_dir<K>(&self, dir: K, key: K) -> Result<Option<Vec<u8>>>;
    fn write<K, V, I>(&self, items: I) -> Result<()>
    where
        I: IntoIterator<Item = (K, V)>;
}
