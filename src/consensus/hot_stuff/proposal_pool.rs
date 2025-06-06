use std::collections::BTreeSet;

use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{
    network::transport::protocols::gossipsub::{self, Payload},
    proposal::Proposal,
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Proposal pool is not started")]
    NotStarted,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Failed to deserialize proposal: {0}")]
    Deserialize(String),
}

enum Action<P: Proposal + Ord> {
    Get,
    Remove(BTreeSet<P>),
}

struct Channel<P: Proposal + Ord> {
    action_tx: Sender<Action<P>>,
    result_rx: Receiver<BTreeSet<P>>,
}

pub struct ProposalPool<P: Proposal + Ord> {
    handle: Option<(JoinHandle<()>, Channel<P>)>,
    capacity: usize,
}

impl<P: Proposal + Ord> ProposalPool<P> {
    pub fn new(capacity: usize) -> Self {
        Self {
            handle: None,
            capacity,
        }
    }

    pub async fn start(&mut self, mut rx: Receiver<gossipsub::Message>) {
        const CHANNEL_CAPACITY: usize = 100;

        if self.handle.is_some() {
            return;
        }

        let (action_tx, mut action_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let capacity = self.capacity;

        let handle = tokio::spawn(async move {
            let mut proposals = BTreeSet::new();

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if let Err(e) = Self::handle_message(msg, &mut proposals, capacity) {
                            log::error!("Failed to handle message: {e}");
                        }
                    },

                    Some(action) = action_rx.recv() => {
                        if let Err(e) = Self::handle_action(action, &mut proposals, &result_tx).await {
                            log::error!("Failed to handle action: {e}");
                        }
                    },

                    else => {
                        log::info!("Proposal pool task completed");
                        break;
                    },
                }
            }
        });

        let channel = Channel {
            action_tx,
            result_rx,
        };

        self.handle = Some((handle, channel));
    }

    fn handle_message(
        msg: gossipsub::Message,
        proposals: &mut BTreeSet<P>,
        capacity: usize,
    ) -> Result<()> {
        if let Payload::Proposal(proposal) = msg.payload {
            let proposal =
                P::from_slice(&proposal).map_err(|e| Error::Deserialize(e.to_string()))?;

            proposals.insert(proposal);

            if proposals.len() > capacity {
                proposals.pop_first();
            }
        }

        Ok(())
    }

    async fn handle_action(
        action: Action<P>,
        proposals: &mut BTreeSet<P>,
        sender: &Sender<BTreeSet<P>>,
    ) -> Result<()> {
        match action {
            Action::Get => {
                let result = std::mem::take(proposals);
                sender.send(result).await.map_err(|_| Error::ChannelClosed)
            }
            Action::Remove(to_remove) => {
                proposals.retain(|p| !to_remove.contains(p));
                Ok(())
            }
        }
    }

    pub async fn get(&mut self) -> Result<BTreeSet<P>> {
        let (_, channel) = self.handle.as_mut().ok_or(Error::NotStarted)?;

        while channel.result_rx.try_recv().is_ok() {}

        channel
            .action_tx
            .send(Action::Get)
            .await
            .map_err(|_| Error::ChannelClosed)?;

        Ok(channel.result_rx.recv().await.unwrap_or_default())
    }
}

impl<P: Proposal + Ord> Drop for ProposalPool<P> {
    fn drop(&mut self) {
        if let Some((handle, _)) = self.handle.take() {
            handle.abort();
        }
    }
}
