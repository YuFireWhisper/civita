use std::{
    borrow::Cow,
    collections::{hash_map, HashMap},
    vec::IntoIter,
};

use libp2p::kad::{store::RecordStore, ProviderRecord, Record, RecordKey};
use thiserror::Error;

use crate::network::transport::libp2p_transport::protocols::kad::{message, payload, Message};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[derive(Error)]
pub enum Error {
    #[error("{0}")]
    Message(#[from] message::Error),
    #[error("{0}")]
    Payload(#[from] payload::Error),
}

pub struct ValidatedStore {
    pub_key: Vec<u8>,
    records: HashMap<RecordKey, Record>,
    providers: HashMap<RecordKey, Vec<ProviderRecord>>,
}

impl ValidatedStore {
    fn validate_record(&self, record: &Record) -> Result<bool> {
        let message = Message::from_bytes(&record.value)?;

        let signature = message.signature;
        let raw_message = message.payload.to_vec()?;

        Ok(signature.validate(&raw_message, &self.pub_key))
    }
}

impl RecordStore for ValidatedStore {
    type RecordsIter<'a> =
        std::iter::Map<hash_map::Values<'a, RecordKey, Record>, fn(&'a Record) -> Cow<'a, Record>>;
    type ProvidedIter<'a> = IntoIter<Cow<'a, ProviderRecord>>;

    fn get(&self, k: &RecordKey) -> Option<std::borrow::Cow<'_, Record>> {
        self.records.get(k).map(Cow::Borrowed)
    }

    fn put(&mut self, r: Record) -> libp2p::kad::store::Result<()> {
        if let Ok(true) = self.validate_record(&r) {
            self.records.insert(r.key.clone(), r);
        }

        Ok(())
    }

    fn remove(&mut self, k: &RecordKey) {
        self.records.remove(k);
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.records.values().map(Cow::Borrowed)
    }

    fn add_provider(&mut self, record: ProviderRecord) -> libp2p::kad::store::Result<()> {
        self.providers
            .entry(record.key.clone())
            .or_default()
            .push(record);
        Ok(())
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        let provided: Vec<Cow<'_, ProviderRecord>> = self
            .providers
            .values()
            .flat_map(|v| v.iter().map(Cow::Borrowed))
            .collect();
        provided.into_iter()
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        self.providers.get(key).cloned().unwrap_or_default()
    }

    fn remove_provider(&mut self, k: &RecordKey, p: &libp2p::PeerId) {
        if let Some(providers) = self.providers.get_mut(k) {
            providers.retain(|provider| provider.provider != *p);
        }
    }
}
