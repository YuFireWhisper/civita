use crate::ty::Command;

pub trait Validator {
    fn validate(cmd: &Command) -> bool;
}

