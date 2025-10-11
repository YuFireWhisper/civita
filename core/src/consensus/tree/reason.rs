use std::fmt;

use crate::ty::atom::{Difficulty, Height};

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
    InvalidNonce,
    InvalidHeight(Height, Height),
    BlockInAtoms,
    MismatchDifficulty(Difficulty, Difficulty),
    EmptyInput,
    DoubleSpend,
    InvalidMmrProof,
    InvalidScriptSig,
    InvalidCommand,
    InvalidAtomThreshold(usize, usize),
    NonBlockParent,
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

    pub fn mismatch_difficulty(expected: Difficulty, actual: Difficulty) -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::MismatchDifficulty(expected, actual),
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

    pub fn invalid_atom_threshold(got: usize, exp: usize) -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::InvalidAtomThreshold(got, exp),
        ))
    }

    pub fn non_block_parent() -> Self {
        Self::Rejected(RejectReason::Inheritalbe(
            InheritableRejectReason::NonBlockParent,
        ))
    }

    pub fn is_ignore(&self) -> bool {
        matches!(self, Self::Ignored(_))
    }
}

impl fmt::Display for InheritableIgnoreReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExisting => write!(f, "already existing"),
            Self::HeightBelowFinalized(height, finalized) => {
                write!(f, "height {} below finalized {}", height, finalized)
            }
        }
    }
}

impl fmt::Display for NonInheritableIgnoreReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyIgnored(reason) => write!(f, "already ignored: {}", reason),
            Self::IgnoredParent(reason) => write!(f, "parent ignored: {}", reason),
        }
    }
}

impl fmt::Display for IgnoreReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inheritalbe(reason) => write!(f, "{}", reason),
            Self::NonInheritable(reason) => write!(f, "{}", reason),
        }
    }
}

impl fmt::Display for InheritableRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfReference => write!(f, "self reference"),
            Self::InvalidNonce => write!(f, "invalid nonce"),
            Self::InvalidHeight(height, parent_height) => {
                write!(f, "invalid height {} (parent: {})", height, parent_height)
            }
            Self::BlockInAtoms => write!(f, "block in atoms"),
            Self::MismatchDifficulty(expected, actual) => {
                write!(
                    f,
                    "difficulty mismatch (expected: {}, actual: {})",
                    expected, actual
                )
            }
            Self::EmptyInput => write!(f, "empty input"),
            Self::DoubleSpend => write!(f, "double spend"),
            Self::InvalidMmrProof => write!(f, "invalid MMR proof"),
            Self::InvalidScriptSig => write!(f, "invalid script signature"),
            Self::InvalidCommand => write!(f, "invalid command"),
            Self::InvalidAtomThreshold(got, exp) => {
                write!(
                    f,
                    "invalid atom threshold (got: {}, expected: {})",
                    got, exp
                )
            }
            Self::NonBlockParent => write!(f, "non-block parent"),
        }
    }
}

impl fmt::Display for NonInheritableRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRejected(reason) => write!(f, "already rejected: {}", reason),
            Self::RejectedParent(reason) => write!(f, "parent rejected: {}", reason),
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inheritalbe(reason) => write!(f, "{}", reason),
            Self::NonInheritable(reason) => write!(f, "{}", reason),
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ignored(reason) => write!(f, "Ignored: {}", reason),
            Self::Rejected(reason) => write!(f, "Rejected: {}", reason),
        }
    }
}
