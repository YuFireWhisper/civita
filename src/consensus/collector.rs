use tokio::{
    sync::{mpsc::Receiver, oneshot},
    task::{JoinError, JoinHandle},
};

use crate::network::transport::protocols::gossipsub;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("Collector is not started")]
    NotStarted,

    #[error("{0}")]
    Join(#[from] JoinError),
}

#[async_trait::async_trait]
pub trait Context: Send + Sync + 'static {
    async fn handle_message(&mut self, msg: gossipsub::Message) -> bool;
}

pub struct Collector<C: Context> {
    handle: Option<(JoinHandle<C>, oneshot::Sender<()>)>,
}

impl<C: Context> Collector<C> {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(&mut self, mut rx: Receiver<gossipsub::Message>, mut ctx: C) {
        let (tx, mut rx_shutdown) = oneshot::channel();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if ctx.handle_message(msg).await {
                            break;
                        }
                    }
                    _ = &mut rx_shutdown => {
                        break;
                    }
                }
            }

            ctx
        });

        self.handle = Some((handle, tx));
    }

    pub async fn stop(&mut self) -> Result<C> {
        let (handle, tx) = self.handle.take().ok_or(Error::NotStarted)?;
        tx.send(()).map_err(|_| Error::NotStarted)?;
        handle.await.map_err(Error::from)
    }
}

impl<C: Context> Default for Collector<C> {
    fn default() -> Self {
        Self { handle: None }
    }
}
