use std::sync::Arc;

use futures::StreamExt;
use libp2p::{
    core::upgrade::{self},
    noise,
    swarm::{self, SwarmEvent},
    Multiaddr, PeerId, Swarm, Transport as _,
};
use tokio::{
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use crate::{
    crypto::SecretKey,
    network::{
        behaviour::{self, Behaviour},
        gossipsub::{self, Gossipsub},
        request_response,
    },
};

pub mod config;
pub mod error;

pub use config::Config;
pub use error::Error;

type Result<T> = std::result::Result<T, Error>;

pub struct Transport {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    gossipsub: Arc<Gossipsub>,
    req_resp: Arc<request_response::RequestResponse>,
    local_peer_id: PeerId,
    listen_addr: Multiaddr,
    sk: SecretKey,
    config: Config,
}

impl Transport {
    pub async fn new(sk: SecretKey, listen_addr: Multiaddr, config: Config) -> Result<Self> {
        let keypair = sk.to_libp2p_key();

        let transport = libp2p::tcp::tokio::Transport::default()
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair).expect("Failed to create Noise config"))
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

        let peer_id = keypair.public().to_peer_id();
        let behaviour = Behaviour::new(keypair, peer_id)?;

        let swarm_config = swarm::Config::with_tokio_executor();
        let mut swarm = Swarm::new(transport, behaviour, peer_id, swarm_config);

        let listen_addr =
            Self::listen_on(&mut swarm, listen_addr, config.check_listen_timeout).await?;

        let swarm = Arc::new(Mutex::new(swarm));

        let gossipsub_config = gossipsub::NetworkConfig {
            timeout: config.wait_for_gossipsub_peer_timeout,
            channel_size: config.channel_capacity,
        };
        let gossipsub = Gossipsub::new_network(swarm.clone(), peer_id, gossipsub_config).await;
        let gossipsub = Arc::new(gossipsub);

        let req_resp = request_response::RequestResponse::new_network(swarm.clone());
        let req_resp = Arc::new(req_resp);

        let transport = Self {
            swarm,
            gossipsub,
            req_resp,
            local_peer_id: peer_id,
            listen_addr,
            sk,
            config,
        };

        transport.receive().await;

        Ok(transport)
    }

    async fn listen_on(
        swarm: &mut Swarm<Behaviour>,
        addr: Multiaddr,
        check_timeout: Duration,
    ) -> Result<Multiaddr> {
        swarm.listen_on(addr)?;

        tokio::time::timeout(check_timeout, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => return Ok(address),
                    SwarmEvent::ListenerError { error, .. } => {
                        return Err(Error::from(error));
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(Error::from)
        .and_then(|result| result)
    }

    async fn receive(&self) {
        let swarm = self.swarm.clone();
        let gossipsub = self.gossipsub.clone();
        let req_resp = self.req_resp.clone();
        let receive_interval = self.config.receive_interval;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = Self::next_behaviour_event(&swarm) => {
                        match event {
                            behaviour::Event::Gossipsub(event) => {
                                if let Err(e) = gossipsub.handle_event(*event).await {
                                    log::error!("Error handling gossipsub event: {e:?}");
                                }
                            },
                            behaviour::Event::RequestResponse(event) => {
                                if let Err(e) = req_resp.handle_event_network(*event).await {
                                    log::error!("Error handling request response event: {e:?}");
                                }
                            },
                            behaviour::Event::Kad(_) => {
                                // Do nothing
                            },
                        }
                    },
                    _ = async { tokio::time::sleep(receive_interval).await } => {},
                }
            }
        });
    }

    async fn next_behaviour_event(swarm: &Arc<Mutex<Swarm<Behaviour>>>) -> behaviour::Event {
        loop {
            if let SwarmEvent::Behaviour(event) = swarm.lock().await.select_next_some().await {
                return event;
            }
        }
    }

    pub async fn swarm<'a>(&'a self) -> Result<MutexGuard<'a, Swarm<Behaviour>>> {
        match tokio::time::timeout(self.config.get_swarm_lock_timeout, self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockContention),
        }
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        let mut swarm = self.swarm().await?;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.add_peer_address(peer_id, addr.clone());
        swarm.dial(addr)?;
        Ok(())
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub fn listen_addr(&self) -> Multiaddr {
        self.listen_addr.clone()
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.sk
    }

    pub fn gossipsub(&self) -> Arc<Gossipsub> {
        self.gossipsub.clone()
    }

    pub fn request_response(&self) -> Arc<request_response::RequestResponse> {
        self.req_resp.clone()
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport")
            .field("swarm", &"Arc<Mutex<Swarm<P2PBehaviour>>>")
            .finish()
    }
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashSet;
//
//     use libp2p::identity::Keypair;
//     use tokio::time::{timeout, Duration};
//
//     use crate::network::transport::{
//         config::Config,
//         protocols::{gossipsub, request_response},
//         test_transport::TestTransport,
//         Transport,
//     };
//
//     const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";
//     const TOPIC: &str = "TOPIC";
//     const PAYLOAD: &[u8] = b"PAYLOAD";
//     const WAIT_MESSAGE_TIMEOUT: Duration = Duration::from_secs(20);
//
//     type Hasher = sha2::Sha256;
//
//     struct TestContext {
//         t1: TestTransport,
//         t2: TestTransport,
//     }
//
//     impl TestContext {
//         async fn connected() -> Self {
//             let t1 = TestTransport::new(LISTEN_ADDR.parse().unwrap()).await;
//             let t2 = TestTransport::new(LISTEN_ADDR.parse().unwrap()).await;
//
//             let t1_addrss = t1.listen_addr().await;
//             let t1_addres = t1_addrss
//                 .first()
//                 .expect("No listen address available")
//                 .clone();
//             let t2_addrss = t2.listen_addr().await;
//             let t2_addres = t2_addrss
//                 .first()
//                 .expect("No listen address available")
//                 .clone();
//
//             t1.p2p
//                 .dial(t2.peer_id, t2_addres)
//                 .await
//                 .expect("Failed to establish connection between transports");
//
//             t2.p2p
//                 .dial(t1.peer_id, t1_addres)
//                 .await
//                 .expect("Failed to establish connection between transports");
//
//             Self { t1, t2 }
//         }
//     }
//
//     #[tokio::test]
//     async fn create_success() {
//         let keypair = Keypair::generate_ed25519();
//         let listen_addr = LISTEN_ADDR.parse().unwrap();
//         let config = Config::default();
//
//         let result = Transport::new(keypair.clone(), listen_addr, config.clone()).await;
//
//         assert!(result.is_ok(), "Failed to create Transport: {result:?}");
//     }
//
//     #[tokio::test]
//     async fn dial_connection() {
//         let mut ctx = TestContext::connected().await;
//
//         let t1_connected = ctx.t1.check_kad_connection(&ctx.t2.peer_id).await;
//         let t2_connected = ctx.t2.check_kad_connection(&ctx.t1.peer_id).await;
//
//         assert!(t1_connected, "Failed to connect t1 to t2");
//         assert!(t2_connected, "Failed to connect t2 to t1");
//     }
//
//     #[tokio::test]
//     async fn listen_on_topic_success() {
//         let ctx = TestContext::connected().await;
//
//         let result = ctx.t1.p2p.listen_on_topic(TOPIC).await;
//
//         assert!(result.is_ok(), "Failed to listen on topic: {result:?}");
//     }
//
//     #[tokio::test]
//     async fn test_publish() {
//         use gossipsub::Payload;
//
//         let ctx = TestContext::connected().await;
//         let payload = Payload::Raw(PAYLOAD.to_vec());
//
//         ctx.t2.p2p.listen_on_topic(TOPIC).await.unwrap();
//
//         let result = ctx.t1.p2p.publish(TOPIC, payload.clone()).await;
//
//         assert!(result.is_ok(), "Failed to publish message: {result:?}");
//     }
//
//     #[tokio::test]
//     async fn test_receive_gossipsub() {
//         use gossipsub::Payload;
//
//         let ctx = TestContext::connected().await;
//         let payload = Payload::Raw(PAYLOAD.to_vec());
//         let mut rx = ctx.t2.p2p.listen_on_topic(TOPIC).await.unwrap();
//
//         ctx.t1.p2p.publish(TOPIC, payload.clone()).await.unwrap();
//
//         let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
//             let msg = rx.recv().await.unwrap();
//             msg.payload == payload
//         })
//         .await
//         .unwrap();
//
//         assert!(result, "Failed to receive message: {result:?}");
//     }
//
//     #[tokio::test]
//     async fn test_receive_request_response() {
//         use request_response::{payload::Request, Payload};
//
//         let ctx = TestContext::connected().await;
//
//         let peers = HashSet::from([ctx.t1.peer_id]);
//
//         let mut rx = ctx.t2.p2p.listen_on_peers(peers).await;
//
//         let request = Request::Raw(PAYLOAD.to_vec());
//         ctx.t1.p2p.request(&ctx.t2.peer_id, request.clone()).await;
//
//         let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
//             let msg = rx.recv().await.unwrap();
//             msg.payload == Payload::Request(request)
//         })
//         .await
//         .unwrap();
//
//         assert!(result, "Failed to receive message: {result:?}");
//     }
// }
//
// #[cfg(test)]
// pub mod test_transport {
//     use libp2p::{identity::Keypair, Multiaddr, PeerId, Swarm};
//     use tokio::sync::MutexGuard;
//
//     use crate::network::transport::{behaviour::Behaviour, config::Config, Transport};
//
//     type Hasher = sha2::Sha256;
//
//     pub struct TestTransport {
//         pub keypair: Keypair,
//         pub peer_id: PeerId,
//         pub config: Config,
//         pub p2p: Transport,
//     }
//
//     impl TestTransport {
//         pub async fn new(listen_addr: Multiaddr) -> Self {
//             let keypair = Keypair::generate_ed25519();
//             let peer_id = PeerId::from_public_key(&keypair.public());
//             let config = Config::default();
//
//             let p2p = Transport::new(keypair.clone(), listen_addr, config.clone())
//                 .await
//                 .unwrap();
//
//             Self {
//                 keypair,
//                 peer_id,
//                 config,
//                 p2p,
//             }
//         }
//
//         pub async fn p2p_swarm(&self) -> MutexGuard<'_, Swarm<Behaviour>> {
//             self.p2p.swarm.lock().await
//         }
//
//         pub async fn check_kad_connection(&mut self, peer_id: &PeerId) -> bool {
//             self.p2p_swarm()
//                 .await
//                 .behaviour_mut()
//                 .kad_mut()
//                 .kbucket(*peer_id)
//                 .is_some()
//         }
//
//         pub async fn listen_addr(&self) -> Vec<Multiaddr> {
//             let swarm = self.p2p_swarm().await;
//             swarm.listeners().cloned().collect()
//         }
//     }
// }
