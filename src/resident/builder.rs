// use std::{str::FromStr, sync::Arc};
//
// use crate::{
//     committee,
//     crypto::{
//         dkg::{self, Dkg, JointFeldman},
//         keypair::{self, KeyType, SecretKey},
//         tss::{self, Tss},
//     },
//     network::transport::{self, protocols::kad},
//     resident::Resident,
// };
//
// #[cfg(not(test))]
// use crate::network::transport::Transport;
//
// #[cfg(test)]
// use crate::network::transport::MockTransport as Transport;
//
// type Result<T> = std::result::Result<T, Error>;
//
// const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
//
// #[derive(Debug)]
// #[derive(thiserror::Error)]
// pub enum Error {
//     #[error("{0}")]
//     Multiaddr(#[from] libp2p::multiaddr::Error),
//
//     #[error("{0}")]
//     Transport(#[from] transport::Error),
//
//     #[error("{0}")]
//     Committee(#[from] committee::Error),
// }
//
// #[derive(Debug)]
// pub enum DkgScheme {
//     JointFeldman(dkg::joint_feldman::Config),
// }
//
// #[derive(Debug)]
// pub enum TssScheme {
//     Schnorr(tss::schnorr::Config),
// }
//
// pub struct Builder {
//     secret_key: Option<SecretKey>,
//     listen_addr: libp2p::Multiaddr,
//     transport_config: transport::Config,
//     dkg_scheme: DkgScheme,
//     tss_scheme: TssScheme,
//     committee_config: committee::Config,
// }
//
// impl Builder {
//     pub fn new() -> Self {
//         Self::default()
//     }
//
//     pub fn with_secret_key(mut self, secret_key: impl Into<SecretKey>) -> Self {
//         self.secret_key = Some(secret_key.into());
//         self
//     }
//
//     pub fn with_listen_addr(mut self, listen_addr: String) -> Result<Self> {
//         self.listen_addr = libp2p::Multiaddr::from_str(&listen_addr)?;
//         Ok(self)
//     }
//
//     pub fn with_transport_config(mut self, config: transport::Config) -> Self {
//         self.transport_config = config;
//         self
//     }
//
//     pub fn with_dkg_scheme(mut self, scheme: DkgScheme) -> Self {
//         self.dkg_scheme = scheme;
//         self
//     }
//
//     pub fn with_tss_scheme(mut self, scheme: TssScheme) -> Self {
//         self.tss_scheme = scheme;
//         self
//     }
//
//     pub async fn build(self) -> Result<Resident<impl Dkg, impl Tss>> {
//         let secret_key = self
//             .secret_key
//             .unwrap_or_else(|| keypair::generate_keypair(KeyType::Secp256k1).0);
//         let public_key = secret_key.to_public_key();
//
//         let keypair = Self::create_keypair(secret_key.as_ref().to_vec());
//
//         let transport = Transport::new(keypair, self.listen_addr, self.transport_config).await?;
//         let transport = Arc::new(transport);
//
//         let dkg = match self.dkg_scheme {
//             DkgScheme::JointFeldman(config) => {
//                 JointFeldman::new(transport.clone(), secret_key.clone(), config)
//             }
//         };
//         let dkg = Arc::new(dkg);
//
//         let tss = match self.tss_scheme {
//             TssScheme::Schnorr(config) => {
//                 tss::schnorr::Schnorr::new(dkg.clone(), transport.clone(), config)
//             }
//         };
//
//         let committee_info = Self::get_committee_info(&transport).await?;
//
//         let committee_config = self.committee_config.to_owned();
//         let committee = committee::Committee::new(
//             transport.clone(),
//             dkg,
//             tss,
//             secret_key,
//             public_key,
//             committee_info,
//             committee_config,
//         )
//         .await?;
//
//         Ok(Resident {
//             transport,
//             committee,
//         })
//     }
//
//     fn create_keypair(mut secret_key_bytes: Vec<u8>) -> libp2p::identity::Keypair {
//         let secret_key =
//             libp2p::identity::secp256k1::SecretKey::try_from_bytes(secret_key_bytes.as_mut_slice())
//                 .expect("Failed to create keypair");
//         libp2p::identity::secp256k1::Keypair::from(secret_key).into()
//     }
//
//     async fn get_committee_info(transport: &Arc<Transport>) -> Result<committee::Info> {
//         match transport
//             .get(kad::Key::CurrentCommitteeInfo)
//             .await?
//             .expect("Failed to get committee info")
//         {
//             kad::Payload::Committee(info) => Ok(info),
//             _ => panic!("Expected committee info"),
//         }
//     }
// }
//
// impl Default for DkgScheme {
//     fn default() -> Self {
//         Self::JointFeldman(dkg::joint_feldman::Config::default())
//     }
// }
//
// impl Default for TssScheme {
//     fn default() -> Self {
//         Self::Schnorr(tss::schnorr::Config::default())
//     }
// }
//
// impl Default for Builder {
//     fn default() -> Self {
//         let listen_addr = libp2p::Multiaddr::from_str(DEFAULT_LISTEN_ADDR)
//             .expect("Failed to parse default listen address");
//
//         Self {
//             secret_key: None,
//             listen_addr,
//             transport_config: transport::Config::default(),
//             dkg_scheme: DkgScheme::default(),
//             tss_scheme: TssScheme::default(),
//             committee_config: committee::Config::default(),
//         }
//     }
// }
