use tokio::task::JoinHandle;

pub(super) struct ReceiveTask<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> ReceiveTask<T> {
    pub fn new() -> Self {
        Self { handle: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestType = u32;

    #[test]
    fn test_new() {
        let task: ReceiveTask<TestType> = ReceiveTask::new();
        assert!(task.handle.is_none());
    }
}
