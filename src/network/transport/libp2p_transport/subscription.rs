use std::collections::HashMap;

use tokio::sync::mpsc::Sender;

use crate::network::{message::Message, transport::SubscriptionFilter};

pub(super) struct Subscription {
    subscriptions: HashMap<SubscriptionFilter, Vec<Sender<Message>>>,
}

impl Subscription {
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
        }
    }

    pub fn add_subscription(&mut self, filter: SubscriptionFilter, sender: Sender<Message>) {
        self.subscriptions.entry(filter).or_default().push(sender);
    }

    pub fn remove_dead_channels(&mut self) {
        self.subscriptions.retain(|_, senders| {
            senders.retain(|sender| !sender.is_closed());
            !senders.is_empty()
        });
    }

    pub fn broadcast(&self, filter: &SubscriptionFilter, message: Message) {
        if let Some(senders) = self.subscriptions.get(filter) {
            for sender in senders {
                let _ = sender.try_send(message.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        sync::mpsc::{channel, Receiver},
        time::timeout,
    };

    use crate::network::message::{gossipsub, Payload};

    use super::*;

    const TEST_TOPIC: &str = "test";

    fn create_subscription() -> Subscription {
        Subscription::new()
    }

    fn create_filter() -> SubscriptionFilter {
        SubscriptionFilter::Topic(TEST_TOPIC.to_string())
    }

    fn create_channel() -> (Sender<Message>, Receiver<Message>) {
        let (sender, receiver) = channel(1);
        (sender, receiver)
    }

    fn create_message() -> Message {
        let payload = Payload::RawData {
            data: vec![1, 2, 3],
        };
        Message::Gossipsub(gossipsub::Message::new(TEST_TOPIC, payload))
    }

    #[test]
    fn test_new() {
        let subscription = create_subscription();
        assert!(subscription.subscriptions.is_empty());
    }

    #[test]
    fn test_add_subscription() {
        let mut subscription = create_subscription();
        let filter = create_filter();
        let (sender, _) = create_channel();

        subscription.add_subscription(filter.clone(), sender);

        assert_eq!(subscription.subscriptions.len(), 1);
        assert_eq!(subscription.subscriptions.get(&filter).unwrap().len(), 1);
    }

    #[test]
    fn test_remove_dead_channels() {
        let mut subscription = create_subscription();
        let filter = create_filter();
        let (sender1, receiver1) = create_channel();
        let (sender2, _receiver2) = create_channel();

        subscription.add_subscription(filter.clone(), sender1);
        subscription.add_subscription(filter.clone(), sender2);
        drop(receiver1);

        subscription.remove_dead_channels();

        assert_eq!(subscription.subscriptions.len(), 1);
        assert_eq!(subscription.subscriptions.get(&filter).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_broadcast_success() {
        let mut subscription = create_subscription();
        let filter = create_filter();
        let (sender1, mut receiver1) = create_channel();
        let (sender2, mut receiver2) = create_channel();

        subscription.add_subscription(filter.clone(), sender1);
        subscription.add_subscription(filter.clone(), sender2);

        let message = create_message();
        subscription.broadcast(&filter, message.clone());

        let received1_message = receiver1.recv().await;
        let received2_message = receiver2.recv().await;

        assert!(received1_message.is_some());
        assert!(received2_message.is_some());
        assert_eq!(received1_message.unwrap(), message);
        assert_eq!(received2_message.unwrap(), message);
    }

    #[tokio::test]
    async fn test_broadcast_non_existent_filter() {
        const SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(100);

        let subscription = create_subscription();
        let filter = create_filter();
        let (_, mut receiver) = create_channel();

        let message = create_message();
        subscription.broadcast(&filter, message.clone());

        let timeout = timeout(SLEEP_TIME, receiver.recv()).await;
        assert!(timeout.is_err() || timeout.unwrap().is_none());
    }
}
