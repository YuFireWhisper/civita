use std::sync::Arc;

use libp2p::identity::Keypair;
use thiserror::Error;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    task::JoinHandle,
};

use crate::network::{
    message::Message,
    transport::{SubscriptionFilter, Transport},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    ReceiveError(String),
}

type VrfResult<T> = Result<T, Error>;

enum State {
    Running(JoinHandle<()>),
    Stopped,
}

impl State {
    fn is_running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    fn stop(&mut self) {
        if let Self::Running(handle) = std::mem::replace(self, Self::Stopped) {
            handle.abort();
        }
    }
}

pub struct VrfProof {
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct Vrf {
    keypair: Arc<Keypair>,
    receiver: Arc<Mutex<Receiver<Message>>>,
    state: Arc<Mutex<State>>,
}

impl Vrf {
    const VRF_TOPIC: &'static str = "vrf";

    pub async fn new(transport: Arc<Transport>, keypair: Arc<Keypair>) -> Self {
        let subscription_filter = Self::generate_vrf_filter();
        let receiver = transport.subscribe(subscription_filter).await;
        let receiver = Arc::new(Mutex::new(receiver));
        let state = Arc::new(Mutex::new(State::Stopped));

        Self {
            keypair,
            receiver,
            state,
        }
    }

    fn generate_vrf_filter() -> SubscriptionFilter {
        SubscriptionFilter::Topic(Self::VRF_TOPIC.to_string())
    }

    pub async fn start(self: Arc<Self>) -> VrfResult<()> {
        if self.is_running().await {
            return Ok(());
        }

        let self_clone = Arc::clone(&self);
        let handle = tokio::spawn(async move {
            while let Some(message) = self_clone.receiver.lock().await.recv().await {
                self_clone.handle_message(&message);
            }

            let mut state = self_clone.state.lock().await;
            *state = State::Stopped;
        });

        self.set_running(handle).await;
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        self.state.lock().await.is_running()
    }

    async fn set_running(self: Arc<Self>, handle: JoinHandle<()>) {
        let mut state = self.state.lock().await;
        *state = State::Running(handle);
    }

    fn handle_message(&self, _message: &Message) {
        todo!()
    }

    pub async fn stop(self: Arc<Self>) {
        self.state.lock().await.stop();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libp2p::identity::Keypair;

    use crate::network::transport::test_transport::TestTransport;

    use super::Vrf;

    async fn generate_new_vrf() -> Arc<Vrf> {
        let transport = TestTransport::new().await.unwrap();
        let transport = Arc::new(transport.p2p);
        let keypair = Arc::new(Keypair::generate_ed25519());

        Arc::new(Vrf::new(transport, keypair).await)
    }

    #[tokio::test]
    async fn test_start_and_stop() {
        let vrf = generate_new_vrf().await;
        assert!(!vrf.is_running().await, "Vrf should not be running");

        vrf.clone().start().await.unwrap();
        assert!(vrf.is_running().await, "Vrf should be running");

        vrf.clone().stop().await;
        assert!(!vrf.is_running().await, "Vrf should not be running");
    }
}
