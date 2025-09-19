type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    RocksDb(#[from] rocksdb::Error),

    #[error("Directory not found")]
    DirNotFound,
}

pub trait Storage {
    fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;
    fn put_with_dir<K, V>(&self, dir: &str, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;
    fn get<K>(&self, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>;
    fn get_with_dir<K>(&self, dir: &str, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>;
    fn write<K, V, I>(&self, items: I) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
        I: IntoIterator<Item = (K, V)>;
}

impl Storage for rocksdb::DB {
    fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.put(key, value).map_err(Error::from)
    }

    fn put_with_dir<K, V>(&self, dir: &str, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let cf = self.cf_handle(dir).ok_or(Error::DirNotFound)?;
        self.put_cf(cf, key, value).map_err(Error::from)
    }

    fn get<K>(&self, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        self.get(key).map_err(Error::from)
    }

    fn get_with_dir<K>(&self, dir: &str, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        let cf = self.cf_handle(dir).ok_or(Error::DirNotFound)?;
        self.get_cf(cf, key).map_err(Error::from)
    }

    fn write<K, V, I>(&self, items: I) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
        I: IntoIterator<Item = (K, V)>,
    {
        let mut batch = rocksdb::WriteBatch::default();
        items.into_iter().for_each(|(k, v)| batch.put(k, v));
        self.write(batch).map_err(Error::from)
    }
}
