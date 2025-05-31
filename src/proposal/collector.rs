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
                    result = rx.recv() => {
                        match result {
                            Some(msg) => ctx.handle_message(msg).await,
                            None => break,
                        }
                    }
                    _ = &mut rx_shutdown => {
                        break;
                    }
                    else => {
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
        let _ = tx.send(());
        handle.await.map_err(Error::from)
    }

    pub async fn wait_for_stop(&mut self, duration: Duration) -> Option<Result<C>> {
        let (handle, _tx) = self.handle.lock().await.take()?;

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

#[cfg(test)]
mod tests {
    use libp2p::{gossipsub::MessageId, PeerId};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, Mutex as AsyncMutex};

    use crate::network::transport::protocols::gossipsub::Payload;

    use super::*;

    const LONG_TIMEOUT: Duration = Duration::from_millis(500);

    #[derive(Debug)]
    struct MockContext {
        messages: Arc<AsyncMutex<Vec<gossipsub::Message>>>,
        delay: Option<Duration>,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                messages: Arc::new(AsyncMutex::new(Vec::new())),
                delay: None,
            }
        }

        fn with_delay(delay: Duration) -> Self {
            Self {
                messages: Arc::new(AsyncMutex::new(Vec::new())),
                delay: Some(delay),
            }
        }

        async fn get_messages(&self) -> Vec<gossipsub::Message> {
            self.messages.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl Context for MockContext {
        async fn handle_message(&mut self, msg: gossipsub::Message) {
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            self.messages.lock().await.push(msg);
        }
    }

    fn create_test_message(id: u8, content: &str) -> gossipsub::Message {
        gossipsub::Message {
            message_id: MessageId::new(&[id]),
            source: PeerId::random(),
            topic: "test-topic".to_string(),
            payload: Payload::Raw(content.as_bytes().to_vec()),
            committee_signature: None,
        }
    }

    #[tokio::test]
    async fn basic_message_handling() {
        let collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        let test_msg = create_test_message(1, "test message");
        tx.send(test_msg.clone()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, test_msg.payload);
    }

    #[tokio::test]
    async fn multiple_message_handling() {
        let collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        // Send multiple messages
        for i in 0..5 {
            let msg = create_test_message(i, &format!("message {i}"));
            tx.send(msg).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(20)).await;

        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 5);
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        let collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        // Send a message
        let test_msg = create_test_message(1, "test");
        tx.send(test_msg).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Stop should return the context with processed messages
        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 1);
    }

    #[tokio::test]
    async fn stop_without_start() {
        let collector = Collector::<MockContext>::new();

        let result = collector.stop().await;

        assert!(matches!(result, Err(Error::NotStarted)));
    }

    #[tokio::test]
    async fn restart_behavior() {
        let collector = Collector::new();
        let (tx1, rx1) = mpsc::channel(10);
        let ctx1 = MockContext::new();

        // Start first time
        collector.start(rx1, ctx1).await;

        let test_msg1 = create_test_message(1, "first message");
        tx1.send(test_msg1).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Start again (should replace the previous task)
        let (tx2, rx2) = mpsc::channel(10);
        let ctx2 = MockContext::new();
        collector.start(rx2, ctx2).await;

        let test_msg2 = create_test_message(2, "second message");
        tx2.send(test_msg2).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].payload,
            Payload::Raw(b"second message".to_vec())
        );
    }

    #[tokio::test]
    async fn channel_closed_handling() {
        let collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        // Close the sender
        drop(tx);

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Collector should still be stoppable
        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 0);
    }

    #[tokio::test]
    async fn wait_for_stop_with_timeout() {
        let mut collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::with_delay(Duration::from_millis(50));

        collector.start(rx, ctx).await;

        // Send a message that will cause delay in processing
        let test_msg = create_test_message(1, "delayed message");
        tx.send(test_msg).await.unwrap();

        // Wait with timeout shorter than processing delay
        let result = collector.wait_for_stop(Duration::from_millis(20)).await;

        // Should return None due to timeout
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn wait_for_stop_completes() {
        let mut collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        let test_msg = create_test_message(1, "test message");
        tx.send(test_msg).await.unwrap();

        // Close channel to trigger completion
        drop(tx);

        let result = collector.wait_for_stop(LONG_TIMEOUT).await;

        assert!(result.is_some());
        let ctx_result = result.unwrap().unwrap();
        let messages = ctx_result.get_messages().await;
        assert_eq!(messages.len(), 1);
    }

    #[tokio::test]
    async fn wait_until_behavior() {
        let mut collector = Collector::new();
        let (tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        let test_msg = create_test_message(1, "test message");
        tx.send(test_msg).await.unwrap();

        let start_time = tokio::time::Instant::now();
        let result_ctx = collector
            .wait_until(Duration::from_millis(50))
            .await
            .unwrap();
        let elapsed = start_time.elapsed();

        // Should wait for the specified duration
        assert!(elapsed >= Duration::from_millis(45)); // Allow some tolerance

        let messages = result_ctx.get_messages().await;
        assert_eq!(messages.len(), 1);
    }

    #[tokio::test]
    async fn wait_until_not_started() {
        let mut collector = Collector::<MockContext>::new();

        let result = collector.wait_until(Duration::from_millis(10)).await;

        assert!(matches!(result, Err(Error::NotStarted)));
    }

    #[tokio::test]
    async fn concurrent_operations() {
        let collector = Arc::new(Collector::new());
        let (tx, rx) = mpsc::channel(100);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        // Spawn multiple tasks sending messages concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let tx_clone = tx.clone();
            let handle = tokio::spawn(async move {
                for j in 0..5 {
                    let msg = create_test_message((i * 5 + j) as u8, &format!("msg-{i}-{i}"));
                    tx_clone.send(msg).await.unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all senders to complete
        for handle in handles {
            handle.await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 50); // 10 tasks * 5 messages each
    }

    #[tokio::test]
    async fn empty_message_stream() {
        let collector = Collector::new();
        let (_tx, rx) = mpsc::channel(10);
        let ctx = MockContext::new();

        collector.start(rx, ctx).await;

        // Don't send any messages, just close the channel
        drop(_tx);

        tokio::time::sleep(Duration::from_millis(20)).await;

        let result_ctx = collector.stop().await.unwrap();
        let messages = result_ctx.get_messages().await;

        assert_eq!(messages.len(), 0);
    }

    #[tokio::test]
    async fn default_constructor() {
        let collector = Collector::<MockContext>::default();

        // Should be in the same state as new()
        let result = collector.stop().await;
        assert!(matches!(result, Err(Error::NotStarted)));
    }
}
