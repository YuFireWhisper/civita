use tokio::sync::{mpsc::Receiver, Mutex, MutexGuard};

use crate::{
    committee::Action, network::transport::libp2p_transport::protocols::gossipsub::Message,
};

pub struct MessageChannels {
    committee_rx: Mutex<Receiver<Message>>,
    sig_req_rx: Mutex<Receiver<Message>>,
    timer_rx: Mutex<Receiver<Action>>,
}

impl MessageChannels {
    pub fn new(
        committee_rx: Receiver<Message>,
        sig_req_rx: Receiver<Message>,
        timer_rx: Receiver<Action>,
    ) -> Self {
        let committee_rx = Mutex::new(committee_rx);
        let sig_req_rx = Mutex::new(sig_req_rx);
        let timer_rx = Mutex::new(timer_rx);

        Self {
            committee_rx,
            sig_req_rx,
            timer_rx,
        }
    }

    pub async fn lock_committee_rx(&self) -> MutexGuard<'_, Receiver<Message>> {
        self.committee_rx.lock().await
    }

    pub async fn lock_sig_req_rx(&self) -> MutexGuard<'_, Receiver<Message>> {
        self.sig_req_rx.lock().await
    }

    pub async fn lock_timer_rx(&self) -> MutexGuard<'_, Receiver<Action>> {
        self.timer_rx.lock().await
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use crate::committee::message_channels::MessageChannels;

    #[tokio::test]
    async fn creates_message_channels() {
        const CHANNEL_SIZE: usize = 1;

        let (_, committee_rx) = mpsc::channel(CHANNEL_SIZE);
        let (_, sig_req_rx) = mpsc::channel(CHANNEL_SIZE);
        let (_, timer_rx) = mpsc::channel(CHANNEL_SIZE);

        let channels = MessageChannels::new(committee_rx, sig_req_rx, timer_rx);

        assert!(channels.lock_committee_rx().await.try_recv().is_err());
        assert!(channels.lock_sig_req_rx().await.try_recv().is_err());
        assert!(channels.lock_timer_rx().await.try_recv().is_err());
    }
}
