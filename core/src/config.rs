use serde::{Deserialize, Serialize};

use crate::crypto::Hasher;

type ValuePk<T> = (<T as Config>::Value, <T as Config>::ScriptPk);
type Diff<T> = Vec<(<T as Config>::Address, Option<ValuePk<T>>)>; // None means deletion

#[derive(Debug)]
#[derive(Clone, Copy)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum PruneMode {
    All,
    Recent(u32),
    Lastest,
}

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
    type Command: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static;
    type Executor: Executor<Self> + Send + Sync + 'static;
    type GenesisConfig: GenesisConfig<Self>;

    const HASHER: Hasher;
    const VDF_PARAM: u16;
    const BLOCK_THRESHOLD: u32;
    const CHECKPOINT_DISTANCE: u32;
    const TARGET_BLOCK_TIME_SEC: u64;
    const MAX_VDF_DIFFICULTY_ADJUSTMENT: f64;
}

pub trait GenesisConfig<T: Config>: Send + Sync + 'static {
    const HEIGHT: u32;
    const VAF_DIFFICULTY: u64;

    fn initial_command() -> Option<T::Command>;
}
