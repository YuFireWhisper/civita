use std::collections::HashMap;

use tokio::sync::mpsc::Sender;

use crate::network::transport::{libp2p_transport::message::Message, Listener};

pub(super) struct ListenerManager {
    listeners: HashMap<Listener, Vec<Sender<Message>>>,
}

impl ListenerManager {
    pub fn new() -> Self {
        let listeners = HashMap::new();
        Self { listeners }
    }

    pub fn add_listener(&mut self, listener: Listener, sender: Sender<Message>) {
        self.listeners.entry(listener).or_default().push(sender);
    }

    pub fn remove_dead_channels(&mut self) {
        self.listeners.retain(|_, senders| {
            senders.retain(|sender| !sender.is_closed());
            !senders.is_empty()
        });
    }

    pub fn broadcast(&self, listener: &Listener, message: Message) {
        if let Some(senders) = self.listeners.get(listener) {
            for sender in senders {
                let _ = sender.try_send(message.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::transport::libp2p_transport::protocols::gossipsub::message::mock_message;

    use super::*;
    use tokio::{
        sync::mpsc::{channel, Receiver},
        time::timeout,
    };

    const TEST_TOPIC: &str = "TEST";

    fn create_manager() -> ListenerManager {
        ListenerManager::new()
    }

    fn create_listener() -> Listener {
        Listener::Topic(TEST_TOPIC.to_string())
    }

    fn create_channel() -> (Sender<Message>, Receiver<Message>) {
        let (sender, receiver) = channel(1);
        (sender, receiver)
    }

    fn create_message() -> Message {
        let gossipsub = mock_message::create_message();
        Message::Gossipsub(gossipsub)
    }

    #[test]
    fn test_new() {
        let manager = create_manager();
        assert!(manager.listeners.is_empty());
    }

    #[test]
    fn test_add_listener() {
        let mut manager = create_manager();
        let listener = create_listener();
        let (sender, _) = create_channel();

        manager.add_listener(listener.clone(), sender);

        assert_eq!(manager.listeners.len(), 1);
        assert_eq!(manager.listeners.get(&listener).unwrap().len(), 1);
    }

    #[test]
    fn test_remove_dead_channels() {
        let mut manager = create_manager();
        let listener = create_listener();
        let (sender1, receiver1) = create_channel();
        let (sender2, _receiver2) = create_channel();

        manager.add_listener(listener.clone(), sender1);
        manager.add_listener(listener.clone(), sender2);
        drop(receiver1);

        manager.remove_dead_channels();

        assert_eq!(manager.listeners.len(), 1);
        assert_eq!(manager.listeners.get(&listener).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_broadcast_success() {
        let mut manager = create_manager();
        let listener = create_listener();
        let (sender1, mut receiver1) = create_channel();
        let (sender2, mut receiver2) = create_channel();

        manager.add_listener(listener.clone(), sender1);
        manager.add_listener(listener.clone(), sender2);

        let message = create_message();
        manager.broadcast(&listener, message.clone());

        let received1_message = receiver1.recv().await;
        let received2_message = receiver2.recv().await;

        assert!(received1_message.is_some());
        assert!(received2_message.is_some());
        assert_eq!(received1_message.unwrap(), message);
        assert_eq!(received2_message.unwrap(), message);
    }

    #[tokio::test]
    async fn test_broadcast_non_existent_listener() {
        const SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(100);

        let manager = create_manager();
        let listener = create_listener();
        let (_, mut receiver) = create_channel();

        let message = create_message();
        manager.broadcast(&listener, message.clone());

        let timeout = timeout(SLEEP_TIME, receiver.recv()).await;
        assert!(timeout.is_err() || timeout.unwrap().is_none());
    }
}
