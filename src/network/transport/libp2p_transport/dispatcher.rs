use std::hash::Hash;

use dashmap::DashMap;
use tokio::sync::mpsc::Sender;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("No such item")]
    NoSuchItem,
    #[error("Failed to send message: {0}")]
    SendFailed(String),
}

pub trait Keyed<K> {
    fn key(&self) -> &K;
}

#[derive(Debug)]
#[derive(Default)]
pub(super) struct Dispatcher<K, T>
where
    K: Hash + Eq,
    T: Keyed<K>,
{
    registered: DashMap<K, Sender<T>>,
}

impl<K, T> Dispatcher<K, T>
where
    K: Hash + Eq,
    T: Keyed<K>,
{
    pub fn new() -> Self {
        Self {
            registered: DashMap::new(),
        }
    }

    pub fn register(&self, key: K, tx: Sender<T>) {
        self.registered.insert(key, tx);
    }

    pub fn register_all(&self, keys: impl IntoIterator<Item = K>, tx: &Sender<T>) {
        for key in keys {
            self.register(key, tx.clone());
        }
    }

    pub fn remove_dead(&self) {
        self.registered.retain(|_, tx| !tx.is_closed());
    }

    pub fn dispatch(&self, value: T) -> Result<()> {
        let key = value.key();
        let sender = self.registered.get(key).ok_or(Error::NoSuchItem)?;
        sender
            .try_send(value)
            .map_err(|e| Error::SendFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use crate::network::transport::libp2p_transport::dispatcher::{Dispatcher, Keyed};

    const CHANNEL_SIZE: usize = 10;

    #[derive(Debug)]
    struct TestMessage {
        key: String,
    }

    impl TestMessage {}

    impl Keyed<String> for TestMessage {
        fn key(&self) -> &String {
            &self.key
        }
    }

    #[test]
    fn create() {
        let dispatcher = Dispatcher::<String, TestMessage>::new();
        assert!(dispatcher.registered.is_empty());
    }

    #[test]
    fn map_len_up_register() {
        const KEY: &str = "test";

        let (tx, _) = mpsc::channel(CHANNEL_SIZE);
        let dispatcher = Dispatcher::<String, TestMessage>::new();
        dispatcher.register(KEY.to_string(), tx);

        assert_eq!(dispatcher.registered.len(), 1);
    }

    #[test]
    fn map_len_up_register_all() {
        const MESSAGE: &str = "test_";
        const NUMBER: usize = 10;

        let keys: Vec<String> = (0..NUMBER).map(|i| format!("{}{}", MESSAGE, i)).collect();

        let (tx, _) = mpsc::channel(CHANNEL_SIZE);
        let dispatcher = Dispatcher::<String, TestMessage>::new();
        dispatcher.register_all(keys.clone(), &tx);

        assert_eq!(dispatcher.registered.len(), NUMBER);
    }

    #[test]
    fn map_len_down_remove_deal() {
        const KEY: &str = "test";

        let (tx, mut rx) = mpsc::channel(CHANNEL_SIZE);
        let dispatcher = Dispatcher::<String, TestMessage>::new();
        dispatcher.register(KEY.to_string(), tx);

        rx.close();
        dispatcher.remove_dead();

        assert_eq!(dispatcher.registered.len(), 0);
    }
}
