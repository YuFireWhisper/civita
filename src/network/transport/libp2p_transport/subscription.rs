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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_subscription() -> Subscription {
        Subscription::new()
    }

    #[test]
    fn test_new() {
        let subscription = create_subscription();
        assert!(subscription.subscriptions.is_empty());
    }
}
