use crate::ty::atom::Height;

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum InheritableIgnoreReason {
    AlreadyExisting,
    HeightBelowFinalized(Height, Height),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum NonInheritableIgnoreReason {
    AlreadyIgnored(InheritableIgnoreReason),
    IgnoredParent(InheritableIgnoreReason),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum IgnoreReason {
    Inheritalbe(InheritableIgnoreReason),
    NonInheritable(NonInheritableIgnoreReason),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum InheritableRejectReason {
    SelfReference,
    ParentInAtoms,
    InvalidNonce,
    InvalidHeight(Height, Height),
    BlockInAtoms,
    MismatchDifficulty(u64, u64),
    IncompleteAtomHistory,
    EmptyInput,
    DoubleSpend,
    InvalidMmrProof,
    InvalidScriptSig,
    InvalidCommand,
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum NonInheritableRejectReason {
    AlreadyRejected(InheritableRejectReason),
    RejectedParent(InheritableRejectReason),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum RejectReason {
    Inheritalbe(InheritableRejectReason),
    NonInheritable(NonInheritableRejectReason),
}

#[derive(Clone, Copy)]
#[derive(Debug)]
pub enum Reason {
    Ignored(IgnoreReason),
    Rejected(RejectReason),
}

impl Reason {
    pub fn inherit(self) -> Self {
        match self {
            Reason::Ignored(r) => match r {
                IgnoreReason::Inheritalbe(r) => Self::Ignored(IgnoreReason::NonInheritable(
                    NonInheritableIgnoreReason::AlreadyIgnored(r),
                )),
                IgnoreReason::NonInheritable(r) => Self::Ignored(IgnoreReason::NonInheritable(r)),
            },
            Reason::Rejected(r) => match r {
                RejectReason::Inheritalbe(r) => Self::Rejected(RejectReason::NonInheritable(
                    NonInheritableRejectReason::AlreadyRejected(r),
                )),
                RejectReason::NonInheritable(r) => Self::Rejected(RejectReason::NonInheritable(r)),
            },
        }
    }

    pub fn inherit_parent(self) -> Self {
        match self {
            Reason::Ignored(r) => match r {
                IgnoreReason::Inheritalbe(r) => Self::Ignored(IgnoreReason::NonInheritable(
                    NonInheritableIgnoreReason::IgnoredParent(r),
                )),
                IgnoreReason::NonInheritable(r) => Self::Ignored(IgnoreReason::NonInheritable(r)),
            },
            Reason::Rejected(r) => match r {
                RejectReason::Inheritalbe(r) => Self::Rejected(RejectReason::NonInheritable(
                    NonInheritableRejectReason::RejectedParent(r),
                )),
                RejectReason::NonInheritable(r) => Self::Rejected(RejectReason::NonInheritable(r)),
            },
        }
    }

    pub fn already_existing() -> Self {
        Self::Ignored(IgnoreReason::Inheritalbe(
            InheritableIgnoreReason::AlreadyExisting,
        ))
    }

    pub fn below_finalized(height: Height, finalized: Height) -> Self {
        Self::Ignored(IgnoreReason::Inheritalbe(
            InheritableIgnoreReason::HeightBelowFinalized(height, finalized),
        ))
    }

    pub fn self_reference() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::SelfReference,
        ))
    }

    pub fn parent_in_atoms() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::ParentInAtoms,
        ))
    }

    pub fn invalid_nonce() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidNonce,
        ))
    }

    pub fn invalid_height(height: Height, parent_height: Height) -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidHeight(height, parent_height),
        ))
    }

    pub fn block_in_atoms() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::BlockInAtoms,
        ))
    }

    pub fn mismatch_difficulty(expected: u64, actual: u64) -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::MismatchDifficulty(expected, actual),
        ))
    }

    pub fn incomplete_atom_history() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::IncompleteAtomHistory,
        ))
    }

    pub fn empty_input() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::EmptyInput,
        ))
    }

    pub fn double_spend() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::DoubleSpend,
        ))
    }

    pub fn invalid_mmr_proof() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidMmrProof,
        ))
    }

    pub fn invalid_script_sig() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidScriptSig,
        ))
    }

    pub fn invalid_command() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidCommand,
        ))
    }
}
