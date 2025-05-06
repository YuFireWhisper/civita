use std::{cmp::Ordering, collections::BinaryHeap, sync::Arc};

use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    time::{self, Instant},
};

#[derive(Debug)]
struct TimerItem<T: Send + 'static> {
    trigger_at: Instant,
    data: T,
}

pub struct Timer<T: Send + 'static> {
    queue: Arc<Mutex<BinaryHeap<TimerItem<T>>>>,
    wakeup_tx: Sender<()>,
}

impl<T: Send + 'static> Timer<T> {
    const CHANNEL_SIZE: usize = 100;

    pub async fn new() -> (Self, Receiver<T>) {
        let (notify_tx, notify_rx) = mpsc::channel(Self::CHANNEL_SIZE);
        let (wakeup_tx, wakeup_rx) = mpsc::channel(1); // Only need capacity of 1 for wakeups

        let queue = Arc::new(Mutex::new(BinaryHeap::new()));

        let timer = Self { queue, wakeup_tx };

        tokio::spawn(timer.clone().run(notify_tx, wakeup_rx));

        (timer, notify_rx)
    }

    async fn run(self, notify_tx: Sender<T>, mut wakeup_rx: Receiver<()>) {
        loop {
            let next_trigger = {
                let queue = self.queue.lock().await;
                queue.peek().map(|item| item.trigger_at)
            };

            match next_trigger {
                Some(trigger_time) => {
                    let now = Instant::now();
                    if trigger_time <= now {
                        self.process_ready_items(&notify_tx).await;
                        continue;
                    }

                    if (Self::sleep_until(trigger_time, &mut wakeup_rx).await).is_err() {
                        break; // Channel closed
                    }
                }
                None => {
                    if wakeup_rx.recv().await.is_none() {
                        break; // Channel closed
                    }
                }
            }
        }
    }

    async fn sleep_until(trigger_time: Instant, wakeup_rx: &mut Receiver<()>) -> Result<(), ()> {
        let sleep_duration = trigger_time.saturating_duration_since(Instant::now());
        tokio::select! {
            _ = time::sleep(sleep_duration) => Ok(()),
            _ = wakeup_rx.recv() => Err(()),
        }
    }

    async fn process_ready_items(&self, notify_tx: &Sender<T>) {
        let now = Instant::now();
        let mut queue = self.queue.lock().await;

        while let Some(item) = queue.peek() {
            if item.trigger_at > now {
                break;
            }

            let item = queue.pop().unwrap();
            if notify_tx.send(item.data).await.is_err() {
                break; // Receiver dropped
            }
        }
    }

    pub async fn schedule(&self, data: T, delay: tokio::time::Duration) {
        let trigger_at = Instant::now() + delay;
        let item = TimerItem { trigger_at, data };

        {
            let mut queue = self.queue.lock().await;
            queue.push(item);
        }

        let _ = self.wakeup_tx.try_send(());
    }
}

impl<T: Send + 'static> Clone for Timer<T> {
    fn clone(&self) -> Self {
        Self {
            queue: Arc::clone(&self.queue),
            wakeup_tx: self.wakeup_tx.clone(),
        }
    }
}

impl<T: Send> PartialEq for TimerItem<T> {
    fn eq(&self, other: &Self) -> bool {
        self.trigger_at == other.trigger_at
    }
}

impl<T: Send> Eq for TimerItem<T> {}

impl<T: Send> PartialOrd for TimerItem<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.trigger_at.cmp(&self.trigger_at))
    }
}

impl<T: Send> Ord for TimerItem<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.trigger_at.cmp(&self.trigger_at)
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{self, Duration};

    use crate::utils::Timer;

    #[tokio::test]
    async fn none_item_time_has_not_passed() {
        const DELAY: Duration = Duration::from_millis(u64::MAX);
        const TEST_STR: &str = "test";

        let (timer, mut rx) = Timer::<String>::new().await;
        timer.schedule(TEST_STR.to_string(), DELAY).await;

        let result = rx.recv().await;

        assert!(result.is_none(), "Expected None, but got {:?}", result);
    }

    #[tokio::test]
    async fn some_item_time_has_passed() {
        const DELAY: Duration = Duration::from_millis(0);
        const TEST_STR: &str = "test";

        let (timer, mut rx) = Timer::<&'static str>::new().await;
        timer.schedule(TEST_STR, DELAY).await;
        time::sleep(Duration::from_millis(1)).await; // Ensure the timer has time to process

        let result = rx.recv().await;

        assert_eq!(
            result,
            Some(TEST_STR),
            "Expected {:?}, but got {:?}",
            TEST_STR,
            result
        );
    }

    #[tokio::test]
    async fn multiple_items() {
        const DELAY: Duration = Duration::from_millis(0);

        let (timer, mut rx) = Timer::<usize>::new().await;

        for i in 0..5 {
            timer.schedule(i, DELAY).await;
        }
        time::sleep(Duration::from_millis(1)).await; // Ensure the timer has time to process

        let mut results = Vec::new();
        for _ in 0..5 {
            if let Some(val) = rx.recv().await {
                results.push(val);
            }
        }

        assert_eq!(results.len(), 5);
        results.sort();
        assert_eq!(results, vec![0, 1, 2, 3, 4]);
    }
}
