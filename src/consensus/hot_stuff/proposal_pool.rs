use std::collections::BTreeSet;

use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{proposal::Proposal, traits::serializable};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Proposal pool is not started")]
    NotStarted,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("{0}")]
    Serializable(#[from] serializable::Error),
}

enum Action<P: Proposal> {
    Get,
    Remove(BTreeSet<P>),
}

pub struct ProposalPool<P: Proposal> {
    handle: JoinHandle<()>,
    action_tx: Sender<Action<P>>,
    result_rx: Receiver<BTreeSet<P>>,
}

impl<P: Proposal> ProposalPool<P> {
    pub fn new(mut rx: Receiver<Vec<u8>>, capacity: usize) -> Self {
        const CHANNEL_CAPACITY: usize = 100;

        let (action_tx, mut action_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (result_tx, result_rx) = mpsc::channel(CHANNEL_CAPACITY);

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

        Self {
            handle,
            action_tx,
            result_rx,
        }
    }

    fn handle_message(msg: Vec<u8>, proposals: &mut BTreeSet<P>, capacity: usize) -> Result<()> {
        let proposal = P::from_slice(&msg)?;

        proposals.insert(proposal);

        if proposals.len() > capacity {
            proposals.pop_first();
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
        while self.result_rx.try_recv().is_ok() {}

        self.action_tx
            .send(Action::Get)
            .await
            .map_err(|_| Error::ChannelClosed)?;

        Ok(self.result_rx.recv().await.unwrap_or_default())
    }

    pub async fn remove(&self, proposals: BTreeSet<P>) -> Result<()> {
        self.action_tx
            .send(Action::Remove(proposals))
            .await
            .map_err(|_| Error::ChannelClosed)?;

        Ok(())
    }
}

impl<P: Proposal> Drop for ProposalPool<P> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
