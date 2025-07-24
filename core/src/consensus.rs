use crate::{consensus::proposal::Proposal, crypto::Multihash};

pub mod block;
pub mod engine;
pub mod proposal;

pub use engine::Engine;

pub enum Event {
    Proposal {
        proposal_id: Multihash,
        proposal: Proposal,
    },
}
