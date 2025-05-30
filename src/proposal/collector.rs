use std::time::Duration;

use tokio::{
    sync::{mpsc::Receiver, oneshot, Mutex},
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
    async fn handle_message(&mut self, msg: gossipsub::Message);
}

pub struct Collector<C: Context> {
    handle: Mutex<Option<(JoinHandle<C>, oneshot::Sender<()>)>>,
}

impl<C: Context> Collector<C> {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(&self, mut rx: Receiver<gossipsub::Message>, mut ctx: C) {
        let (tx, mut rx_shutdown) = oneshot::channel();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        ctx.handle_message(msg).await;
                    }
                    _ = &mut rx_shutdown => {
                        break;
                    }
                }
            }

            ctx
        });

        if let Some((h, _)) = self.handle.lock().await.replace((handle, tx)) {
            h.abort()
        }
    }

    pub async fn stop(&self) -> Result<C> {
        let (handle, tx) = self.handle.lock().await.take().ok_or(Error::NotStarted)?;
        tx.send(()).map_err(|_| Error::NotStarted)?;
        handle.await.map_err(Error::from)
    }

    pub async fn wait_for_stop(&mut self, duration: Duration) -> Option<Result<C>> {
        let (handle, _) = self.handle.lock().await.take()?;

        match tokio::time::timeout(duration, handle).await {
            Ok(join_result) => Some(join_result.map_err(Error::from)),
            Err(_) => None,
        }
    }

    pub async fn wait_until(&mut self, duration: Duration) -> Result<C> {
        tokio::time::sleep(duration).await;
        self.stop().await
    }
}

impl<C: Context> Default for Collector<C> {
    fn default() -> Self {
        Self {
            handle: Mutex::new(None),
        }
    }
}
