use crate::{proposal::Proposal, CerditType};

pub enum RecordKey {
    Resident(libp2p::PeerId),
    Proposal([u8; 32]),
}

pub enum RecordValue<T, P: Proposal> {
    Resident(ResidentRecord<T>),
    Proposal(P),
}

pub enum ResidentRecord<T> {
    Credit(CerditType),
    Custom(T),
}
