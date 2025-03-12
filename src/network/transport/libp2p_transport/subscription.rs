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
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::channel;

    use super::*;

    const TEST_TOPIC: &str = "test";

    fn create_subscription() -> Subscription {
        Subscription::new()
    }

    fn create_filter() -> SubscriptionFilter {
        SubscriptionFilter::Topic(TEST_TOPIC.to_string())
    }

    fn create_sender() -> Sender<Message> {
        let (sender, _) = channel(1);
        sender
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
        let sender = create_sender();

        subscription.add_subscription(filter.clone(), sender);

        assert_eq!(subscription.subscriptions.len(), 1);
        assert_eq!(subscription.subscriptions.get(&filter).unwrap().len(), 1);
    }
}
