pub mod committee;
pub mod community;
pub mod crypto;
pub mod network;

#[derive(Debug)]
pub struct MockError;

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mock error")
    }
}

impl std::error::Error for MockError {}
