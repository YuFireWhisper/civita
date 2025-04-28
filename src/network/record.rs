use crate::{proposal::Proposal, CerditType};

/// A 32-byte key used to identify a `Record`.
/// - For the `Resident` variant, the `RecordKey` is the [`PeerId`] of the resident
/// - For the `Proposal` variant, the `RecordKey` is the hash of the proposal.
///
/// [`PeerId`]: https://docs.rs/libp2p/latest/libp2p/struct.PeerId.html
pub type RecordKey = [u8; 32];

pub enum Record<T, P: Proposal> {
    Resident { cerdit: CerditType, custom: T },
    Proposal(P),
}
