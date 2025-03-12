use tokio::task::JoinHandle;

pub(super) struct ReceiveTask<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> ReceiveTask<T> {
    pub fn new() -> Self {
        Self { handle: None }
    }

    pub fn is_running(&self) -> bool {
        self.handle.is_some() && !self.handle.as_ref().unwrap().is_finished() // unwrap is safe
    }

    pub fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }

    pub fn set_handle(&mut self, handle: JoinHandle<T>) {
        self.stop(); // We don't use if judgement, which is faster
        self.handle = Some(handle);
    }
}

#[cfg(test)]
mod tests {
    use tokio::{
        spawn,
        time::{sleep, Duration},
    };

    use super::*;

    type TestType = bool;

    const TEST_DURATION: Duration = Duration::from_millis(100);
    const TEST_VALUE: TestType = true;

    fn create_task() -> ReceiveTask<TestType> {
        ReceiveTask::new()
    }

    #[test]
    fn test_new() {
        let task = create_task();
        assert!(task.handle.is_none(), "Handle should be None");
    }

    #[test]
    fn test_is_running_init() {
        let task = create_task();
        assert!(!task.is_running(), "Task should not be running");
    }

    #[tokio::test]
    async fn test_is_running_true() {
        let mut task = create_task();
        task.handle = Some(spawn(async {
            sleep(TEST_DURATION).await;
            TEST_VALUE
        }));
        assert!(task.is_running(), "Task should be running");
    }

    #[tokio::test]
    async fn test_is_running_false() {
        let mut task = create_task();
        task.handle = Some(spawn(async { TEST_VALUE }));
        sleep(TEST_DURATION).await;
        assert!(!task.is_running(), "Task should not be running");
    }

    #[tokio::test]
    async fn test_stop() {
        let mut task = create_task();
        task.handle = Some(spawn(async {
            sleep(TEST_DURATION).await;
            TEST_VALUE
        }));
        let is_running_before = task.is_running();
        task.stop();
        let is_running_after = task.is_running();

        assert!(is_running_before, "Task should be running before stop");
        assert!(!is_running_after, "Task should not be running after stop");
    }

    #[tokio::test]
    async fn test_set_handle() {
        let mut task = create_task();
        task.handle = Some(spawn(async {
            sleep(TEST_DURATION).await;
            TEST_VALUE
        }));
        let is_running_before = task.is_running();
        task.set_handle(spawn(async { TEST_VALUE }));
        let is_running_after = task.is_running();

        assert!(
            is_running_before,
            "Task should be running before set_handle"
        );
        assert!(is_running_after, "Task should be running after set_handle");
    }
}
