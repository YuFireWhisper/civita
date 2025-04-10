use std::fmt::Debug;

#[derive(Clone, Copy)]
#[derive(Debug)]
pub struct Counter {
    counter_fn: fn(u16) -> u16,
}

impl Counter {
    pub fn new(f: fn(u16) -> u16) -> Self {
        Self { counter_fn: f }
    }

    pub fn call(&self, n: u16) -> u16 {
        (self.counter_fn)(n)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new(|n| 2 * n / 3 + 1)
    }
}
