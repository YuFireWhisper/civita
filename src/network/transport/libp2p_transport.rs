pub mod behaviour;
pub mod config;
pub mod listener_manager;
pub mod message;
pub mod protocols;
pub mod receive_task;

use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc};

use behaviour::{Behaviour, Event};
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    gossipsub::{IdentTopic, MessageId, TopicHash},
    identity::Keypair,
    noise,
    swarm::{self, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use log::{info, warn};
use receive_task::ReceiveTask;
use tokio::{
    sync::{
        mpsc::{channel, Receiver},
        Mutex, MutexGuard, RwLock,
    },
    time::{interval, sleep, timeout, Duration, Interval},
};

use crate::network::transport::libp2p_transport::{
    config::Config,
    listener_manager::ListenerManager,
    message::Message,
    protocols::{
        gossipsub,
        request_response::{self, payload::Request},
    },
};

use super::{Error, Listener, Transport};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Libp2pTransport {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    receive_task: Arc<Mutex<ReceiveTask<Result<()>>>>,
    keypair: Arc<Keypair>,
    listener_manager: Arc<RwLock<ListenerManager>>,
    config: Config,
    subscribed_topics: Arc<Mutex<HashSet<TopicHash>>>,
}

impl Libp2pTransport {
    pub async fn new(keypair: Keypair, listen_addr: Multiaddr, config: Config) -> Result<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = Behaviour::new(keypair.clone())?;
        let peer_id = Self::create_peer_id(&keypair);
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            peer_id,
            swarm::Config::with_tokio_executor(),
        );

        Self::listen_on(&mut swarm, listen_addr, config.check_listen_timeout).await?;

        let swarm = Arc::new(Mutex::new(swarm));
        let receive_task = Arc::new(Mutex::new(ReceiveTask::new()));
        let keypair = Arc::new(keypair);
        let listener_manager = Arc::new(RwLock::new(ListenerManager::new()));
        let subscribed_topics = Arc::new(Mutex::new(HashSet::new()));

        let transport = Self {
            swarm,
            receive_task,
            keypair,
            listener_manager,
            config,
            subscribed_topics,
        };

        transport.receive().await;

        Ok(transport)
    }

    fn create_transport(keypair: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        use libp2p::Transport; // If import at the top, it will conflict with Self

        tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed()
    }

    fn create_peer_id(keypair: &Keypair) -> PeerId {
        PeerId::from_public_key(&keypair.public())
    }

    async fn listen_on(
        swarm: &mut Swarm<Behaviour>,
        addr: Multiaddr,
        check_timeout: Duration,
    ) -> Result<()> {
        swarm.listen_on(addr)?;

        timeout(check_timeout, async {
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { .. } => return Ok(()),
                    SwarmEvent::ListenerError { error, .. } => {
                        return Err(Error::ListenerFailed(error.to_string()))
                    }
                    _ => continue,
                }
            }
        })
        .await
        .map_err(|_| Error::BindTimeout)?
    }

    async fn receive(&self) {
        let arc_self = Arc::new(self.clone());
        tokio::spawn(async move {
            let mut cleanup_tick = interval(arc_self.config.cleanup_channel_interval);

            loop {
                tokio::select! {
                    _ = arc_self.clone().cleanup_channels(&mut cleanup_tick) => {},
                    event = arc_self.clone().next_behaviour_event() => {
                        if let Err(e) = arc_self.clone().process_event(event).await {
                            warn!("Failed to process event: {:?}", e);
                        }
                    },
                    _ = async { sleep(arc_self.config.wait_for_gossipsub_peer_timeout).await } => {},
                }
            }
        });
    }

    async fn cleanup_channels(self: Arc<Self>, interval: &mut Interval) {
        interval.tick().await;
        let mut subs = self.listener_manager.write().await;
        subs.remove_dead_channels();
    }

    async fn next_behaviour_event(self: Arc<Self>) -> Event {
        loop {
            match self.swarm_without_timeout().await.select_next_some().await {
                SwarmEvent::Behaviour(event) => return event,
                _ => continue,
            }
        }
    }

    async fn swarm_without_timeout(self: &Arc<Self>) -> MutexGuard<'_, Swarm<Behaviour>> {
        self.swarm.lock().await
    }

    async fn process_event(self: Arc<Self>, event: Event) -> Result<()> {
        if let Event::Gossipsub(event) = &event {
            if let libp2p::gossipsub::Event::Subscribed { topic, .. } = &**event {
                self.subscribed_topics.lock().await.insert(topic.clone());
                return Ok(());
            }
        }

        match Message::try_from(event)? {
            Message::Gossipsub(msg) => {
                self.handle_gossipsub_event(msg).await;
                Ok(())
            }
            Message::Kad(msg) => {
                Self::handle_kad_event(msg);
                Ok(())
            }
            Message::RequestResponse(msg) => {
                self.handle_request_response_event(msg).await;
                Ok(())
            }
        }
    }

    async fn handle_gossipsub_event(self: Arc<Self>, message: gossipsub::Message) {
        let topic = &message.topic;
        let topic_filter = Listener::Topic(topic.clone());
        let msg = Message::Gossipsub(message);

        self.listener_manager
            .read()
            .await
            .broadcast(&topic_filter, msg);
    }

    fn handle_kad_event(message: protocols::kad::Message) {
        println!("Kademlia event: {:?}", message);
    }

    async fn handle_request_response_event(self: Arc<Self>, message: request_response::Message) {
        let filter = Listener::Peer(vec![message.peer]);
        let msg = Message::RequestResponse(message);

        self.listener_manager.read().await.broadcast(&filter, msg);
    }

    async fn wait_for_gossipsub_subscription(&self, topic: &TopicHash) -> bool {
        timeout(self.config.wait_for_gossipsub_peer_timeout, async {
            loop {
                if self.subscribed_topics.lock().await.contains(topic) {
                    return true;
                }
                sleep(self.config.wait_for_gossipsub_peer_interval).await;
            }
        })
        .await
        .unwrap_or(false)
    }

    async fn confirm_connection(&self, peer: PeerId) -> Result<()> {
        if let Ok(swarm) = self.try_lock_swarm() {
            if swarm.is_connected(&peer) {
                return Ok(());
            }
        }

        timeout(self.config.check_dial_timeout, async {
            let mut swarm = self.swarm.lock().await;
            tokio::select! {
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => {
                            info!("Connection established with {}", peer);
                            return Ok(());
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } if peer_id == peer => {
                            return Err(Error::ConnectionFailed(error.to_string()));
                        }
                        _ => {
                            if swarm.is_connected(&peer) {
                                return Ok(());
                            }
                        }
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::ConnectTimeout)?
    }

    async fn subscribe(&self, topic: &str) -> Result<()> {
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().gossipsub_mut().subscribe(&topic)?;
        Ok(())
    }

    pub async fn swarm(&self) -> Result<MutexGuard<'_, Swarm<Behaviour>>> {
        match timeout(self.config.get_swarm_lock_timeout, self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockContention),
        }
    }

    pub fn try_lock_swarm(&self) -> Result<MutexGuard<'_, Swarm<Behaviour>>> {
        match self.swarm.try_lock() {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockContention),
        }
    }

    pub async fn is_receiving(&self) -> bool {
        self.receive_task.lock().await.is_running()
    }
}

impl Transport for Libp2pTransport {
    fn dial(
        &self,
        peer_id: PeerId,
        addr: Multiaddr,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let mut swarm = self.swarm().await?;
            swarm
                .behaviour_mut()
                .kad_mut()
                .add_address(&peer_id, addr.clone());
            swarm.add_peer_address(peer_id, addr.clone());
            swarm.dial(addr)?;
            drop(swarm);
            self.confirm_connection(peer_id).await?;
            Ok(())
        })
    }

    fn listen(
        &self,
        listener: Listener,
    ) -> Pin<Box<dyn Future<Output = Result<Receiver<Message>>> + Send + '_>> {
        Box::pin(async move {
            if let Listener::Topic(topic) = &listener {
                self.subscribe(topic).await?;
            }

            let (tx, rx) = channel(self.config.channel_capacity);
            self.listener_manager
                .write()
                .await
                .add_listener(listener, tx);
            Ok(rx)
        })
    }

    fn publish<'a>(
        &'a self,
        topic_str: &'a str,
        payload: gossipsub::Payload,
    ) -> Pin<Box<dyn Future<Output = Result<MessageId>> + Send + 'a>> {
        Box::pin(async move {
            let topic = IdentTopic::new(topic_str);
            if !self.wait_for_gossipsub_subscription(&topic.hash()).await {
                return Err(Error::NoPeerListen(topic_str.to_string()));
            }

            let data: Vec<u8> = payload.try_into()?;
            let mut swarm = self.swarm().await?;
            swarm
                .behaviour_mut()
                .gossipsub_mut()
                .publish(topic.clone(), data.clone())
                .map_err(Error::from)
        })
    }

    fn request<'a>(
        &'a self,
        peer_id: PeerId,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut swarm = self.swarm().await?;
            swarm
                .behaviour_mut()
                .request_response_mut()
                .send_request(&peer_id, request);
            Ok(())
        })
    }
}

impl std::fmt::Debug for Libp2pTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PCommunication")
            .field(
                "receive_task",
                &format!(
                    "{}",
                    self.receive_task
                        .try_lock()
                        .map(|s| s.is_running())
                        .unwrap_or(false)
                ),
            )
            .field("swarm", &"Arc<Mutex<Swarm<P2PBehaviour>>>")
            .finish()
    }
}

impl PartialEq for Libp2pTransport {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.public() == other.keypair.public()
    }
}

#[cfg(test)]
mod tests {
    use crate::network::transport::{
        libp2p_transport::{
            config::Config,
            message::Message,
            protocols::{
                gossipsub,
                request_response::{payload::Request, Payload},
            },
            test_transport::TestTransport,
            Libp2pTransport,
        },
        Listener, Transport,
    };
    use libp2p::identity::Keypair;
    use tokio::time::{timeout, Duration};

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
            let t1 = TestTransport::new(LISTEN_ADDR.parse().unwrap())
                .await
                .expect("Failed to create first transport");
            let t2 = TestTransport::new(LISTEN_ADDR.parse().unwrap())
                .await
                .expect("Failed to create second transport");

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
    async fn test_new() {
        let keypair = Keypair::generate_ed25519();
        let listen_addr = LISTEN_ADDR.parse().unwrap();
        let config = Config::default();

        let result = Libp2pTransport::new(keypair.clone(), listen_addr, config.clone()).await;

        assert!(
            result.is_ok(),
            "Failed to create Libp2pTransport: {:?}",
            result
        );
        assert!(
            !result.as_ref().unwrap().is_receiving().await,
            "Receiving task should not be running"
        );
        assert_eq!(result.as_ref().unwrap().config, config);
    }

    #[tokio::test]
    async fn test_dial() {
        let mut ctx = TestContext::connected().await;

        let t1_connected = ctx.t1.check_kad_connection(&ctx.t2.peer_id).await;
        let t2_connected = ctx.t2.check_kad_connection(&ctx.t1.peer_id).await;

        assert!(t1_connected, "Failed to connect t1 to t2");
        assert!(t2_connected, "Failed to connect t2 to t1");
    }

    #[tokio::test]
    async fn test_listen() {
        let ctx = TestContext::connected().await;
        let filter = Listener::Topic(TOPIC.to_string());

        let result = ctx.t2.p2p.listen(filter).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().capacity(), ctx.t1.config.channel_capacity);
    }

    #[tokio::test]
    async fn test_publish() {
        use gossipsub::Payload;

        let ctx = TestContext::connected().await;
        let listener = Listener::Topic(TOPIC.to_string());
        let payload = Payload::Raw(PAYLOAD.to_vec());

        ctx.t2.p2p.listen(listener).await.unwrap();

        let result = ctx.t1.p2p.publish(TOPIC, payload.clone()).await;

        assert!(result.is_ok(), "Failed to publish message: {:?}", result);
    }

    #[tokio::test]
    async fn test_request() {
        let ctx = TestContext::connected().await;
        let request = Request::Raw(PAYLOAD.to_vec());

        let result = ctx.t1.p2p.request(ctx.t2.peer_id, request.clone()).await;

        assert!(result.is_ok(), "Failed to send request: {:?}", result);
    }

    #[tokio::test]
    async fn test_receive_gossipsub() {
        use gossipsub::Payload;

        let ctx = TestContext::connected().await;
        let payload = Payload::Raw(PAYLOAD.to_vec());
        let filter = Listener::Topic(TOPIC.to_string());
        let mut rx = ctx.t2.p2p.listen(filter).await.unwrap();

        ctx.t1.p2p.publish(TOPIC, payload.clone()).await.unwrap();

        let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
            let msg = rx.recv().await.unwrap();

            if let Message::Gossipsub(msg) = msg {
                msg.payload == payload
            } else {
                false
            }
        })
        .await
        .unwrap();

        assert!(result, "Failed to receive message: {:?}", result);
    }

    #[tokio::test]
    async fn test_receive_request_response() {
        let ctx = TestContext::connected().await;

        let listener = Listener::Peer(vec![ctx.t1.peer_id]);
        let mut rx = ctx.t2.p2p.listen(listener).await.unwrap();

        let request = Request::Raw(PAYLOAD.to_vec());
        ctx.t1
            .p2p
            .request(ctx.t2.peer_id, request.clone())
            .await
            .unwrap();

        let result = timeout(WAIT_MESSAGE_TIMEOUT, async {
            let msg = rx.recv().await.unwrap();
            if let Message::RequestResponse(msg) = msg {
                msg.payload == Payload::Request(request)
            } else {
                false
            }
        })
        .await
        .unwrap();

        assert!(result, "Failed to receive message: {:?}", result);
    }
}

#[cfg(test)]
pub mod test_transport {
    use std::{
        error::Error,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use libp2p::{
        futures::StreamExt, gossipsub, identity::Keypair, request_response, swarm::SwarmEvent,
        Multiaddr, PeerId, Swarm,
    };
    use tokio::{
        sync::MutexGuard,
        task::JoinHandle,
        time::{sleep, Duration},
    };

    use crate::network::transport::libp2p_transport::{
        behaviour::{Behaviour, Event},
        config::Config,
        protocols::request_response::payload::Request,
        Libp2pTransport,
    };

    pub struct TestTransport {
        pub keypair: Keypair,
        pub peer_id: PeerId,
        pub config: Config,
        pub p2p: Libp2pTransport,
    }

    impl TestTransport {
        pub async fn new(listen_addr: Multiaddr) -> Result<Self, Box<dyn Error>> {
            let keypair = Keypair::generate_ed25519();
            let peer_id = PeerId::from_public_key(&keypair.public());
            let config = Config::default();

            let p2p = Libp2pTransport::new(keypair.clone(), listen_addr, config.clone()).await?;

            Ok(Self {
                keypair,
                peer_id,
                config,
                p2p,
            })
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

        pub async fn wait_for_message(
            &self,
            expected: Vec<u8>,
            flag: Arc<AtomicBool>,
        ) -> JoinHandle<()> {
            let swarm = self.p2p.swarm.clone();
            let expected = expected.clone();
            let flag = flag.clone();

            tokio::spawn(async move {
                loop {
                    let mut swarm = swarm.lock().await;
                    let event = swarm.select_next_some().await;
                    drop(swarm);
                    println!("Got Event: {:?}", event);
                    if Self::check_gossipsub_message(&expected, &event)
                        || Self::check_request_message(&expected, &event)
                    {
                        flag.store(true, Ordering::Relaxed);
                        break;
                    }
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }

        fn check_gossipsub_message(expected: &[u8], event: &SwarmEvent<Event>) -> bool {
            if let SwarmEvent::Behaviour(Event::Gossipsub(gossipsub_event)) = event {
                println!("Gossipsub event: {:?}", gossipsub_event);
                if let gossipsub::Event::Message { message, .. } = &**gossipsub_event {
                    return message.data == expected;
                }
            }
            false
        }

        fn check_request_message(expected: &[u8], event: &SwarmEvent<Event>) -> bool {
            matches!(event,
                SwarmEvent::Behaviour(Event::RequestResponse(
                    request_response::Event::Message {
                        message: request_response::Message::Request { request, .. },
                        ..
                    }
                )) if {
                    println!("RequestResponse event: {:?}", request);
                    println!("Expected: {:?}", expected);
                    let expected = Request::try_from(expected.to_vec()).unwrap();
                    request == &expected
                }
            )
        }
    }
}
