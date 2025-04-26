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

pub trait KeyMatcher<K> {
    fn matches(&self, key: &K) -> bool;
}

pub trait Keyed<K> {
    fn key(&self) -> &K;
}

#[derive(Debug)]
#[derive(Default)]
pub(super) struct Dispatcher<K, T>
where
    K: Hash + Eq + KeyMatcher<K>,
    T: Keyed<K>,
{
    registered: DashMap<K, Sender<T>>,
}

impl<K, T> Dispatcher<K, T>
where
    K: Hash + Eq + KeyMatcher<K>,
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

        let matched = self.find_matching_sender(key)?;

        matched
            .try_send(value)
            .map_err(|e| Error::SendFailed(e.to_string()))
    }

    fn find_matching_sender(&self, key: &K) -> Result<Sender<T>>
    where
        K: KeyMatcher<K>,
    {
        if let Some(sender) = self.registered.get(key) {
            return Ok(sender.clone());
        }

        for pair in self.registered.iter() {
            if key.matches(pair.key()) {
                return Ok(pair.value().clone());
            }
        }

        Err(Error::NoSuchItem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    const DEFAULT_CHANNEL_SIZE: usize = 10;
    const MATCH_KEY: &str = "match_key";
    const NON_MATCH_KEY: &str = "non_match_key";

    #[derive(Clone)]
    #[derive(Debug)]
    #[derive(Hash)]
    #[derive(Eq, PartialEq)]
    struct TestKey(String);

    impl KeyMatcher<TestKey> for TestKey {
        fn matches(&self, key: &TestKey) -> bool {
            self.0 == key.0 || self.0 == MATCH_KEY
        }
    }

    #[derive(Debug, Clone)]
    struct TestValue {
        key: TestKey,
        value: String,
    }

    impl Keyed<TestKey> for TestValue {
        fn key(&self) -> &TestKey {
            &self.key
        }
    }

    fn create_test_dispatcher() -> Dispatcher<TestKey, TestValue> {
        Dispatcher::new()
    }

    fn create_channel() -> (Sender<TestValue>, mpsc::Receiver<TestValue>) {
        mpsc::channel(DEFAULT_CHANNEL_SIZE)
    }

    fn create_test_value(key: &str, value: &str) -> TestValue {
        TestValue {
            key: TestKey(key.to_string()),
            value: value.to_string(),
        }
    }

    #[tokio::test]
    async fn new_creates_empty_dispatcher() {
        let dispatcher = create_test_dispatcher();
        assert_eq!(dispatcher.registered.len(), 0);
    }

    #[tokio::test]
    async fn register_adds_sender_to_dispatcher() {
        let dispatcher = create_test_dispatcher();
        let (tx, _rx) = create_channel();

        dispatcher.register(TestKey("key1".to_string()), tx);

        assert_eq!(dispatcher.registered.len(), 1);
        assert!(dispatcher
            .registered
            .contains_key(&TestKey("key1".to_string())));
    }

    #[tokio::test]
    async fn register_all_adds_multiple_senders() {
        let dispatcher = create_test_dispatcher();
        let (tx, _rx) = create_channel();
        let keys = vec![
            TestKey("key1".to_string()),
            TestKey("key2".to_string()),
            TestKey("key3".to_string()),
        ];

        dispatcher.register_all(keys, &tx);

        assert_eq!(dispatcher.registered.len(), 3);
        assert!(dispatcher
            .registered
            .contains_key(&TestKey("key1".to_string())));
        assert!(dispatcher
            .registered
            .contains_key(&TestKey("key2".to_string())));
        assert!(dispatcher
            .registered
            .contains_key(&TestKey("key3".to_string())));
    }

    #[tokio::test]
    async fn remove_dead_removes_closed_senders() {
        let dispatcher = create_test_dispatcher();

        let (tx1, rx1) = create_channel();
        dispatcher.register(TestKey("key1".to_string()), tx1);

        let (tx2, _rx2) = create_channel();
        dispatcher.register(TestKey("key2".to_string()), tx2);

        drop(rx1);

        dispatcher.remove_dead();

        assert_eq!(dispatcher.registered.len(), 1);
        assert!(!dispatcher
            .registered
            .contains_key(&TestKey("key1".to_string())));
        assert!(dispatcher
            .registered
            .contains_key(&TestKey("key2".to_string())));
    }

    #[tokio::test]
    async fn dispatch_sends_to_exact_key_match() {
        let dispatcher = create_test_dispatcher();
        let (tx, mut rx) = create_channel();
        let test_key = "test_key";

        dispatcher.register(TestKey(test_key.to_string()), tx);

        let test_value = create_test_value(test_key, "value");
        let result = dispatcher.dispatch(test_value.clone());

        assert!(result.is_ok());

        let received = rx.try_recv().unwrap();
        assert_eq!(received.key.0, test_key);
        assert_eq!(received.value, "value");
    }

    #[tokio::test]
    async fn dispatch_sends_to_matching_key() {
        let dispatcher = create_test_dispatcher();
        let (tx, mut rx) = create_channel();

        dispatcher.register(TestKey(MATCH_KEY.to_string()), tx);

        let test_value = create_test_value("specific_key", "value");
        let result = dispatcher.dispatch(test_value.clone());

        assert!(result.is_ok());

        let received = rx.try_recv().unwrap();
        assert_eq!(received.key.0, "specific_key");
        assert_eq!(received.value, "value");
    }

    #[tokio::test]
    async fn dispatch_returns_error_when_no_matching_key() {
        let dispatcher = create_test_dispatcher();
        let (tx, _rx) = create_channel();

        dispatcher.register(TestKey("other_key".to_string()), tx);

        let test_value = create_test_value(NON_MATCH_KEY, "value");
        let result = dispatcher.dispatch(test_value);

        assert!(matches!(result, Err(Error::NoSuchItem)));
    }

    #[tokio::test]
    async fn dispatch_returns_error_when_send_fails() {
        let dispatcher = create_test_dispatcher();
        let (tx, rx) = create_channel();

        dispatcher.register(TestKey("key".to_string()), tx.clone());

        for i in 0..DEFAULT_CHANNEL_SIZE {
            let _ = tx.try_send(create_test_value("key", &format!("value{}", i)));
        }
        drop(rx);

        let test_value = create_test_value("key", "overflow_value");
        let result = dispatcher.dispatch(test_value);

        assert!(matches!(result, Err(Error::SendFailed(_))));
    }

    #[tokio::test]
    async fn find_matching_sender_returns_pattern_match_when_no_exact() {
        let dispatcher = create_test_dispatcher();
        let (tx, _rx) = create_channel();

        dispatcher.register(TestKey(MATCH_KEY.to_string()), tx);

        let result = dispatcher.find_matching_sender(&TestKey("no_exact_key".to_string()));

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn find_matching_sender_returns_error_when_no_match() {
        let dispatcher = create_test_dispatcher();

        let result = dispatcher.find_matching_sender(&TestKey(NON_MATCH_KEY.to_string()));

        assert!(matches!(result, Err(Error::NoSuchItem)));
    }

    #[tokio::test]
    async fn concurrent_register_and_dispatch() {
        let dispatcher = Arc::new(create_test_dispatcher());
        let received_values = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();

        for i in 0..5 {
            let (tx, mut rx) = create_channel();
            let key = format!("key{}", i);
            dispatcher.register(TestKey(key), tx);

            let received_clone = Arc::clone(&received_values);
            let handle = tokio::spawn(async move {
                if let Some(val) = rx.recv().await {
                    let mut values = received_clone.lock().unwrap();
                    values.push(val.value);
                }
            });
            handles.push(handle);
        }

        for i in 0..5 {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            let test_value = create_test_value(&key, &value);
            let _ = dispatcher.dispatch(test_value);
        }

        for handle in handles {
            let _ = handle.await;
        }

        let values = received_values.lock().unwrap();
        assert_eq!(values.len(), 5);
        for i in 0..5 {
            assert!(values.contains(&format!("value{}", i)));
        }
    }
}
