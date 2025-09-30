use serde::{Deserialize, Serialize};

use crate::crypto::Hasher;

type ValuePk<T> = (<T as Config>::Value, <T as Config>::ScriptPk);
type Diff<T> = Vec<(<T as Config>::Address, Option<ValuePk<T>>)>; // None means deletion

pub trait Executor<T: Config> {
    fn execute(
        &self,
        value: &T::Value,
        pk: &T::ScriptPk,
        sig: &T::ScriptSig,
    ) -> Result<Diff<T>, String>;
}

pub trait Config: Sized + Send + Sync + 'static {
    type Address: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type Value: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type ScriptPk: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type ScriptSig: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type Command: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type Executor: Executor<Self> + Send + Sync + 'static;
    type GenesisConfig: GenesisConfig<Self>;

    const HASHER: Hasher;
    const VDF_PARAM: u16;
}

pub trait GenesisConfig<T: Config>: Send + Sync + 'static {
    const HEIGHT: u32;
    const VAF_DIFFICULTY: u64;

    fn initial_state() -> Vec<(T::Address, ValuePk<T>)>;
}
