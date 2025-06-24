pub mod block;
pub mod quorum_certificate;
pub mod view;

pub use block::Block;
pub use quorum_certificate::QuorumCertificate;
pub use view::View;

pub type ViewNumber = u64;
