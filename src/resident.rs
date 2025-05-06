// use std::sync::Arc;
//
// use crate::{
//     committee::Committee,
//     crypto::{dkg::Dkg, tss::Tss},
//     network::transport,
// };
//
// #[cfg(not(test))]
// use crate::network::transport::Transport;
//
// #[cfg(test)]
// use crate::network::transport::MockTransport as Transport;
//
// pub mod builder;
//
// type Result<T> = std::result::Result<T, Error>;
//
// #[derive(Debug)]
// #[derive(thiserror::Error)]
// pub enum Error {
//     #[error("{0}")]
//     Transport(#[from] transport::Error),
// }
//
// pub struct Resident<D: Dkg + 'static, T: Tss + 'static> {
//     transport: Arc<Transport>,
//     committee: Arc<Committee<D, T>>,
// }
//
// impl<D: Dkg, T: Tss> Resident<D, T> {}
