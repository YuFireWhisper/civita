use std::{collections::HashSet, sync::Arc};

use tokio::{
    sync::oneshot,
    task::{JoinError, JoinHandle},
};

#[cfg(not(test))]
use crate::network::transport::Transport;
use crate::{
    constants::HashArray,
    network::transport::{self, protocols::gossipsub, store::merkle_dag::Node},
};

#[cfg(test)]
use crate::network::transport::MockTransport as Transport;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] transport::Error),

    #[error("Collector not started")]
    NotStarted,

    #[error("{0}")]
    Join(#[from] JoinError),

    #[error("Fialed to send shutdown signal")]
    SendFailed,
}

pub struct ProposalCollector {
    transport: Arc<Transport>,
    handle: Option<(JoinHandle<HashSet<HashArray>>, oneshot::Sender<()>)>,
}

impl ProposalCollector {
    pub fn new(transport: Arc<Transport>) -> Self {
        ProposalCollector {
            transport,
            handle: None,
        }
    }

    pub async fn start(&mut self, topic: &str) -> Result<()> {
        let mut rx = self.transport.listen_on_topic(topic).await?;
        let transport = self.transport.clone();

        let (oneshot_tx, mut oneshot_rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            let mut proposals = HashSet::new();

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if let gossipsub::Payload::Proposal(hash) = msg.payload {
                            if Self::is_valid_proposal(&transport, hash)
                                .await
                                .unwrap_or(false)
                            {
                                proposals.insert(hash);
                            }
                        }
                    }
                    _ = &mut oneshot_rx => {
                        break;
                    }
                }
            }

            proposals
        });

        self.handle = Some((handle, oneshot_tx));

        Ok(())
    }

    async fn is_valid_proposal(transport: &Transport, hash: HashArray) -> Result<bool> {
        transport
            .get::<Node>(&hash)
            .await
            .map(|opt| opt.is_some())
            .map_err(Error::from)
    }

    pub async fn settle(&mut self) -> Result<HashSet<HashArray>> {
        if let Some((handle, oneshot_tx)) = self.handle.take() {
            oneshot_tx.send(()).map_err(|_| Error::SendFailed)?;
            handle.await.map_err(Error::from)
        } else {
            Err(Error::NotStarted)
        }
    }
}
