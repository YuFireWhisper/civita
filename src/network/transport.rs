use std::{collections::HashSet, fmt::Display, sync::Arc};

use futures::StreamExt;
use libp2p::PeerId;
use tokio::sync::mpsc::Receiver;

use crate::{
    crypto::{traits::hasher::HashArray, tss::Signature, Hasher},
    network::transport::{
        behaviour::Behaviour,
        protocols::{
            gossipsub,
            kad::{self},
            request_response::{self, payload::Request},
            Gossipsub, Kad, RequestResponse,
        },
    },
};

pub mod config;
pub mod error;
pub mod protocols;
pub mod store;

mod behaviour;
mod dispatcher;

pub use config::Config;
pub use error::Error;

type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
enum KadResult {
    PutSuccess,
    PutFailure(Vec<u8>),
    GetSuccess(Vec<u8>),
    GetFailure(Vec<u8>),
    GetNotFound,
}

pub struct Transport {
    swarm: Arc<tokio::sync::Mutex<libp2p::Swarm<Behaviour>>>,
    gossipsub: Arc<Gossipsub>,
    kad: Arc<Kad>,
    request_response: Arc<RequestResponse>,
    keypair: Arc<libp2p::identity::Keypair>,
    config: Config,
    self_peer: PeerId,
}

#[mockall::automock]
impl Transport {
    pub async fn new<T: Into<libp2p::identity::Keypair> + 'static>(
        secret_key: T,
        listen_addr: libp2p::Multiaddr,
        config: Config,
    ) -> Result<Self> {
        let keypair: libp2p::identity::Keypair = secret_key.into();

        let transport = Self::create_transport(keypair.clone());
        let behaviour = Behaviour::new(keypair.clone())?;
        let peer_id = PeerId::from_public_key(&keypair.public());
        let swarm_config = libp2p::swarm::Config::with_tokio_executor();
        let mut swarm = libp2p::Swarm::new(transport, behaviour, peer_id, swarm_config);

        Self::listen_on(&mut swarm, listen_addr, config.check_listen_timeout).await?;

        let swarm = Arc::new(tokio::sync::Mutex::new(swarm));
        let gossipsub_config = gossipsub::ConfigBuilder::new()
            .with_timeout(config.wait_for_gossipsub_peer_timeout)
            .with_channel_size(config.channel_capacity)
            .build();
        let gossipsub = Gossipsub::new(swarm.clone(), gossipsub_config);

        let kad_config = kad::ConfigBuilder::new()
            .wait_for_kad_result_timeout(config.wait_for_kad_result_timeout)
            .build();
        let kad = Kad::new(swarm.clone(), kad_config);

        let request_response_config = request_response::ConfigBuilder::new()
            .with_channel_size(config.channel_capacity)
            .build();
        let request_response = RequestResponse::new(swarm.clone(), request_response_config);

        let keypair = Arc::new(keypair);
        let self_peer = peer_id;

        let transport = Self {
            swarm,
            gossipsub: Arc::new(gossipsub),
            kad: Arc::new(kad),
            request_response: Arc::new(request_response),
            keypair,
            config,
            self_peer,
        };

        transport.receive().await;

        Ok(transport)
    }

    fn create_transport(
        keypair: libp2p::identity::Keypair,
    ) -> libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)> {
        use libp2p::Transport;

        libp2p::tcp::tokio::Transport::default()
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(libp2p::noise::Config::new(&keypair).unwrap())
            .multiplex(libp2p::yamux::Config::default())
            .boxed()
    }

    async fn listen_on(
        swarm: &mut libp2p::Swarm<Behaviour>,
        addr: libp2p::Multiaddr,
        check_timeout: tokio::time::Duration,
    ) -> Result<()> {
        use libp2p::swarm::SwarmEvent;

        swarm.listen_on(addr)?;

        tokio::time::timeout(check_timeout, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { .. } => return Ok(()),
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
        let kad = self.kad.clone();
        let request_response = self.request_response.clone();
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
                            behaviour::Event::Kad(event) => {
                                kad.handle_event(event);
                            },
                            behaviour::Event::RequestResponse(event) => {
                                if let Err(e) = request_response.handle_event(event) {
                                    log::error!("Error handling request-response event: {e:?}");
                                }
                            },
                        }
                    },
                    _ = async { tokio::time::sleep(receive_interval).await } => {},
                }
            }
        });
    }

    async fn next_behaviour_event(
        swarm: &Arc<tokio::sync::Mutex<libp2p::Swarm<Behaviour>>>,
    ) -> behaviour::Event {
        loop {
            if let libp2p::swarm::SwarmEvent::Behaviour(event) =
                swarm.lock().await.select_next_some().await
            {
                return event;
            }
        }
    }

    pub async fn swarm<'a>(
        &'a self,
    ) -> Result<tokio::sync::MutexGuard<'a, libp2p::Swarm<Behaviour>>> {
        match tokio::time::timeout(self.config.get_swarm_lock_timeout, self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockContention),
        }
    }

    pub async fn dial(&self, peer_id: PeerId, addr: libp2p::Multiaddr) -> Result<()> {
        let mut swarm = self.swarm().await?;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.add_peer_address(peer_id, addr.clone());
        swarm.dial(addr)?;
        Ok(())
    }

    pub async fn listen_on_topic(&self, topic: &str) -> Result<Receiver<gossipsub::Message>> {
        self.gossipsub.subscribe(topic).await.map_err(Error::from)
    }

    pub async fn listen_on_peers(
        &self,
        peers: HashSet<PeerId>,
    ) -> tokio::sync::mpsc::Receiver<request_response::Message> {
        self.request_response.listen(peers)
    }

    pub async fn publish(
        &self,
        topic: &str,
        payload: gossipsub::Payload,
    ) -> Result<libp2p::gossipsub::MessageId> {
        self.gossipsub
            .publish(topic, payload)
            .await
            .map_err(Error::from)
    }

    pub async fn request(&self, peer_id: &PeerId, request: Request) {
        self.request_response.request(peer_id, request).await
    }

    pub async fn put<H: Hasher>(&self, record: Vec<u8>) -> Result<()> {
        self.kad.put::<H>(record).await.map_err(Error::from)
    }

    pub async fn get<T: TryFrom<Vec<u8>, Error: Display> + 'static, H: Hasher>(
        &self,
        key: &HashArray<H>,
    ) -> Result<Option<T>> {
        self.kad.get::<T, H>(key).await.map_err(Error::from)
    }

    pub async fn get_or_error<T: TryFrom<Vec<u8>, Error: Display> + 'static, H: Hasher>(
        &self,
        key: &HashArray<H>,
    ) -> Result<T> {
        self.kad
            .get_or_error::<T, H>(key)
            .await
            .map_err(Error::from)
    }

    pub fn self_peer(&self) -> PeerId {
        self.self_peer
    }

    pub fn keypair(&self) -> &libp2p::identity::Keypair {
        self.keypair.as_ref()
    }
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PCommunication")
            .field("swarm", &"Arc<Mutex<Swarm<P2PBehaviour>>>")
            .finish()
    }
}

impl PartialEq for Transport {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.public() == other.keypair.public()
    }
}

impl MockTransport {
    pub fn new_empty() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use libp2p::identity::Keypair;
    use tokio::time::{timeout, Duration};

    use crate::network::transport::{
        config::Config,
        protocols::{gossipsub, request_response},
        test_transport::TestTransport,
        Transport,
    };

    const LISTEN_ADDR: &str = "/ip4/127.0.0.1/tcp/0";
    const TOPIC: &str = "TOPIC";
    const PAYLOAD: &[u8] = b"PAYLOAD";
    const WAIT_MESSAGE_TIMEOUT: Duration = Duration::from_secs(20);

    struct TestContext {
        t1: TestTransport,
        t2: TestTransport,
    }

    impl TestContext {
        async fn connected() -> Self {
            let t1 = TestTransport::new(LISTEN_ADDR.parse().unwrap()).await;
            let t2 = TestTransport::new(LISTEN_ADDR.parse().unwrap()).await;

            let t1_addrss = t1.listen_addr().await;
            let t1_addres = t1_addrss
                .first()
                .expect("No listen address available")
                .clone();
            let t2_addrss = t2.listen_addr().await;
            let t2_addres = t2_addrss
                .first()
                .expect("No listen address available")
                .clone();

            t1.p2p
                .dial(t2.peer_id, t2_addres)
                .await
                .expect("Failed to establish connection between transports");

            t2.p2p
                .dial(t1.peer_id, t1_addres)
                .await
                .expect("Failed to establish connection between transports");

            Self { t1, t2 }
        }
    }

    #[tokio::test]
    async fn create_success() {
        let keypair = Keypair::generate_ed25519();
        let listen_addr = LISTEN_ADDR.parse().unwrap();
        let config = Config::default();

        let result = Transport::new(keypair.clone(), listen_addr, config.clone()).await;

        assert!(result.is_ok(), "Failed to create Transport: {result:?}");
    }

    #[tokio::test]
    async fn dial_connection() {
        let mut ctx = TestContext::connected().await;

        let t1_connected = ctx.t1.check_kad_connection(&ctx.t2.peer_id).await;
        let t2_connected = ctx.t2.check_kad_connection(&ctx.t1.peer_id).await;

        assert!(t1_connected, "Failed to connect t1 to t2");
        assert!(t2_connected, "Failed to connect t2 to t1");
    }

    #[tokio::test]
    async fn listen_on_topic_success() {
        let ctx = TestContext::connected().await;

        let result = ctx.t1.p2p.listen_on_topic(TOPIC).await;

        assert!(result.is_ok(), "Failed to listen on topic: {result:?}");
    }

    #[tokio::test]
    async fn test_publish() {
        use gossipsub::Payload;

        let ctx = TestContext::connected().await;
        let payload = Payload::Raw(PAYLOAD.to_vec());

        ctx.t2.p2p.listen_on_topic(TOPIC).await.unwrap();

        let result = ctx.t1.p2p.publish(TOPIC, payload.clone()).await;

        assert!(result.is_ok(), "Failed to publish message: {result:?}");
    }

    #[tokio::test]
    async fn test_receive_gossipsub() {
        use gossipsub::Payload;

        let ctx = TestContext::connected().await;
        let payload = Payload::Raw(PAYLOAD.to_vec());
        let mut rx = ctx.t2.p2p.listen_on_topic(TOPIC).await.unwrap();

        ctx.t1.p2p.publish(TOPIC, payload.clone()).await.unwrap();

        let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
            let msg = rx.recv().await.unwrap();
            msg.payload == payload
        })
        .await
        .unwrap();

        assert!(result, "Failed to receive message: {result:?}");
    }

    #[tokio::test]
    async fn test_receive_request_response() {
        use request_response::{payload::Request, Payload};

        let ctx = TestContext::connected().await;

        let peers = HashSet::from([ctx.t1.peer_id]);

        let mut rx = ctx.t2.p2p.listen_on_peers(peers).await;

        let request = Request::Raw(PAYLOAD.to_vec());
        ctx.t1.p2p.request(&ctx.t2.peer_id, request.clone()).await;

        let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
            let msg = rx.recv().await.unwrap();
            msg.payload == Payload::Request(request)
        })
        .await
        .unwrap();

        assert!(result, "Failed to receive message: {result:?}");
    }
}

#[cfg(test)]
pub mod test_transport {
    use libp2p::{identity::Keypair, Multiaddr, PeerId, Swarm};
    use tokio::sync::MutexGuard;

    use crate::network::transport::{behaviour::Behaviour, config::Config, Transport};

    pub struct TestTransport {
        pub keypair: Keypair,
        pub peer_id: PeerId,
        pub config: Config,
        pub p2p: Transport,
    }

    impl TestTransport {
        pub async fn new(listen_addr: Multiaddr) -> Self {
            let keypair = Keypair::generate_ed25519();
            let peer_id = PeerId::from_public_key(&keypair.public());
            let config = Config::default();

            let p2p = Transport::new(keypair.clone(), listen_addr, config.clone())
                .await
                .unwrap();

            Self {
                keypair,
                peer_id,
                config,
                p2p,
            }
        }

        pub async fn p2p_swarm(&self) -> MutexGuard<'_, Swarm<Behaviour>> {
            self.p2p.swarm.lock().await
        }

        pub async fn check_kad_connection(&mut self, peer_id: &PeerId) -> bool {
            self.p2p_swarm()
                .await
                .behaviour_mut()
                .kad_mut()
                .kbucket(*peer_id)
                .is_some()
        }

        pub async fn listen_addr(&self) -> Vec<Multiaddr> {
            let swarm = self.p2p_swarm().await;
            swarm.listeners().cloned().collect()
        }
    }
}
