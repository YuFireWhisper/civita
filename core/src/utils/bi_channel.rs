use tokio::sync::mpsc::{self, error::SendError};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
#[derive(thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    SendError(String),

    #[error("Channel closed")]
    ChannelClosed,
}

pub struct BiChannel<T, U> {
    pub tx: mpsc::Sender<T>,
    pub rx: mpsc::Receiver<U>,
}

impl<T, U> BiChannel<T, U> {
    pub async fn send(&self, item: T) -> Result<()> {
        self.tx.send(item).await.map_err(Error::from)
    }

    pub async fn recv_some(&mut self) -> Result<U> {
        self.rx.recv().await.ok_or(Error::ChannelClosed)
    }
}

pub fn bi_channel<T, U>(cap: usize) -> (BiChannel<T, U>, BiChannel<U, T>) {
    let (tx1, rx1) = mpsc::channel(cap);
    let (tx2, rx2) = mpsc::channel(cap);

    (
        BiChannel { tx: tx1, rx: rx2 },
        BiChannel { tx: tx2, rx: rx1 },
    )
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        Error::SendError(e.to_string())
    }
}
