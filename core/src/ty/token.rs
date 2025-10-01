use derivative::Derivative;

use crate::traits::Config;

#[derive(Derivative)]
#[derivative(Clone(bound = "T: Config"))]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Token<T: Config> {
    pub value: T::Value,
    pub script_pk: T::ScriptPk,
}

impl<T: Config> Token<T> {
    pub fn new(value: T::Value, script_pk: T::ScriptPk) -> Self {
        Self { value, script_pk }
    }
}
