pub mod vrf;

use std::sync::{atomic::AtomicBool, Arc};

use tokio::sync::{mpsc::Receiver, Mutex};

use crate::network::{
    message::Message,
    transport::{SubscriptionFilter, Transport},
};

use super::vrf::Vrf;

pub struct Service {
    vrf_receiver: Arc<Mutex<Receiver<Message>>>,
    vrf: Vrf,
    is_running: Arc<AtomicBool>,
}

impl Service {
    const VRF_TOPIC: &'static str = "vrf";

    pub async fn new(transport: Arc<Transport>, vrf: Vrf) -> Self {
        let subscription_filter = Self::generate_vrf_filter();
        let receiver = transport.subscribe(subscription_filter).await;
        let vrf_receiver = Arc::new(Mutex::new(receiver));
        let is_running = Arc::new(AtomicBool::new(false));

        Self {
            vrf_receiver,
            vrf,
            is_running,
        }
    }

    fn generate_vrf_filter() -> SubscriptionFilter {
        SubscriptionFilter::Topic(Self::VRF_TOPIC.to_string())
    }
}
