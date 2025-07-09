pub mod block;
pub mod quorum_certificate;
pub mod view;

pub use block::Block;
pub use quorum_certificate::QuorumCertificate;
pub use view::View;

use crate::{consensus::randomizer::DrawProof, utils::mpt};

pub type ViewNumber = u64;

pub(super) type ProofPair = (DrawProof, mpt::Proof);
