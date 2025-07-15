use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use tokio::sync::mpsc;

use crate::{
    crypto::{Hasher, Multihash},
    proposal::Proposal,
    utils::bi_channel::{self, BiChannel},
};

type Channel = BiChannel<Proposal, Proposal>;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Channel(#[from] bi_channel::Error),
}

pub struct ProposalPool {
    pending: DashMap<Multihash, Proposal>,
    executed: DashSet<Multihash>,
}

impl ProposalPool {
    pub fn new<H: Hasher>(channel: Channel, rx: mpsc::Receiver<Proposal>) -> Arc<Self> {
        let pool = Self {
            pending: DashMap::new(),
            executed: DashSet::new(),
        };

        let pool = Arc::new(pool);
        let pool_clone = Arc::clone(&pool);

        tokio::spawn(async move {
            pool_clone.run::<H>(channel, rx).await;
        });

        pool
    }

    async fn run<H: Hasher>(&self, mut channel: Channel, mut rx: mpsc::Receiver<Proposal>) {
        tokio::select! {
            Some(prop) = rx.recv() => {
                if let Err(e) = channel.send(prop).await {
                    log::error!("Failed to send proposal: {e}");
                }
            }
            res = channel.recv_some() => {
                let Ok(prop) = res else {
                    log::error!("Channel closed while receiving proposal");
                    return;
                };

                self.pending.insert(prop.hash::<H>(), prop);
            }
        }
    }

    pub fn get_pending(&self) -> Vec<Proposal> {
        self.pending
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn is_executed(&self, hash: &Multihash) -> bool {
        self.executed.contains(hash)
    }

    pub fn mark_executed<I>(&self, hashes: I)
    where
        I: IntoIterator<Item = Multihash>,
    {
        for hash in hashes {
            self.executed.insert(hash);
            self.pending.remove(&hash);
        }
    }
}
