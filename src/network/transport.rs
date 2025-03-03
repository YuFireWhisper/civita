use std::{io, sync::Arc};

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    futures::StreamExt,
    gossipsub::{self, IdentTopic},
    identity::Keypair,
    noise,
    swarm::{self, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use thiserror::Error;
use tokio::{
    sync::{Mutex, MutexGuard},
    task::JoinHandle,
    time::{self, sleep, Duration},
};

use super::{
    message::{self, Message},
    p2p_behaviour::{self, P2PBehaviour, P2PEvent},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("{0}")]
    Dial(#[from] swarm::DialError),
    #[error("{0}")]
    Subscribe(#[from] gossipsub::SubscriptionError),
    #[error("{0}")]
    Publish(#[from] gossipsub::PublishError),
    #[error("{0}")]
    P2PBehaviour(#[from] p2p_behaviour::Error),
    #[error("{0}")]
    Message(#[from] message::Error),
    #[error("Failed to lock")]
    LockError,
}

type TransportResult<T> = Result<T, Error>;

enum ReceiveTaskState {
    Running(JoinHandle<TransportResult<()>>),
    Stopped,
}

impl ReceiveTaskState {
    fn is_running(&self) -> bool {
        matches!(self, ReceiveTaskState::Running(_))
    }

    fn stop(&mut self) {
        if let ReceiveTaskState::Running(handle) =
            std::mem::replace(self, ReceiveTaskState::Stopped)
        {
            handle.abort();
        }
    }
}

pub struct Transport {
    swarm: Arc<Mutex<Swarm<P2PBehaviour>>>,
    receive_task: Arc<Mutex<ReceiveTaskState>>,
    keypair: Arc<Keypair>,
    receive_timeout: Duration,
}

impl Transport {
    pub fn new(
        keypair: Keypair,
        listen_addr: Multiaddr,
        receive_timeout: Duration,
    ) -> TransportResult<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = P2PBehaviour::new(keypair.clone())?;

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            PeerId::from_public_key(&keypair.public()),
            swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(listen_addr)?;

        let swarm = Mutex::new(swarm);
        let receive_task = Arc::new(Mutex::new(ReceiveTaskState::Stopped));
        let keypair = Arc::new(keypair);

        Ok(Self {
            swarm: Arc::new(swarm),
            receive_task,
            keypair,
            receive_timeout,
        })
    }

    fn create_transport(keypair: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        use libp2p::Transport; // If import at the top, it will conflict with Self

        tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed()
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> TransportResult<()> {
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.dial(addr)?;
        Ok(())
    }

    pub async fn subscribe(&self, topic: &str) -> TransportResult<()> {
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().gossipsub_mut().subscribe(&topic)?;
        Ok(())
    }

    pub async fn publish(&self, topic: &str, data: impl Into<Vec<u8>>) -> TransportResult<()> {
        let message = Message::new(topic, data.into());
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, message)?;
        Ok(())
    }

    pub async fn receive<T>(&mut self, handler: T)
    where
        T: Fn(Message) + Send + Sync + 'static,
    {
        let mut task_state = self.receive_task.lock().await;
        if task_state.is_running() {
            return;
        }

        let swarm = self.swarm.clone();
        let receive_timeout = self.receive_timeout;
        let receive_task = Arc::clone(&self.receive_task);

        let task = tokio::spawn(async move {
            let handler = Arc::new(handler);

            loop {
                if let Ok(state) = receive_task.try_lock() {
                    if !state.is_running() {
                        break Ok(());
                    }
                }

                let event = {
                    let mut swarm_lock = swarm.lock().await;
                    tokio::select! {
                        event = swarm_lock.select_next_some() => Some(event),
                        _ = sleep(receive_timeout) => None,
                    }
                };

                if let Some(SwarmEvent::Behaviour(P2PEvent::Gossipsub(event))) = event {
                    if let gossipsub::Event::Message { message, .. } = *event {
                        match Message::try_from(message) {
                            Ok(msg) => {
                                let handler = Arc::clone(&handler);
                                tokio::spawn(async move {
                                    handler(msg);
                                });
                            }
                            Err(e) => eprintln!("Error converting message: {}", e),
                        }
                    }
                }
            }
        });

        *task_state = ReceiveTaskState::Running(task);
    }

    pub fn stop_receive(&self) -> TransportResult<()> {
        if let Ok(mut task_state) = self.receive_task.try_lock() {
            task_state.stop();
        }
        Ok(())
    }

    pub async fn swarm(&self) -> TransportResult<MutexGuard<'_, Swarm<P2PBehaviour>>> {
        self.get_swarm_lock().await
    }

    async fn get_swarm_lock(&self) -> TransportResult<MutexGuard<'_, Swarm<P2PBehaviour>>> {
        match time::timeout(Duration::from_secs(5), self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockError),
        }
    }

    pub async fn is_receiving(&self) -> bool {
        self.receive_task.lock().await.is_running()
    }

    pub async fn clone<T>(&self, handler: T) -> Self
    where
        T: Fn(Message) + Send + Sync + 'static,
    {
        let swarm = Arc::clone(&self.swarm);
        let keypair = self.keypair.clone();
        let receive_timeout = self.receive_timeout;

        let mut cloned = Self {
            swarm,
            receive_task: Arc::new(Mutex::new(ReceiveTaskState::Stopped)),
            keypair,
            receive_timeout,
        };

        if self.is_receiving().await {
            cloned.receive(handler).await;
        }

        cloned
    }
}

impl std::fmt::Debug for Transport {
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

impl PartialEq for Transport {
    fn eq(&self, other: &Self) -> bool {
        self.keypair.public() == other.keypair.public()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{atomic::AtomicBool, Arc};

    use tokio::time::Duration;

    use crate::network::transport::test_communication::{
        TestCommunication, TEST_TIMEOUT_DURATION, TEST_TOPIC,
    };

    #[tokio::test]
    async fn test_new() {
        let result = TestCommunication::new().await;
        assert!(
            result.is_ok(),
            "Failed to create P2PCommunication: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dial() {
        let target = TestCommunication::new().await.unwrap();
        let mut source = TestCommunication::new().await.unwrap();

        let result = source
            .p2p
            .dial(target.peer_id, target.listen_addr.clone())
            .await;
        let received_kad_event = source.wait_for_kad_event().await;

        assert!(result.is_ok(), "Dial operation should succeed");
        assert!(
            received_kad_event,
            "Should receive Kademlia event after dialing"
        );
        assert!(
            source.has_peer_in_routing_table(&target.peer_id).await,
            "Target peer should be in the routing table after dialing"
        );
    }

    #[tokio::test]
    async fn test_subscribe() {
        let comm = TestCommunication::new()
            .await
            .expect("Failed to create P2PCommunication");

        let subscribe_result = comm.p2p.subscribe(TEST_TOPIC).await;
        assert!(
            subscribe_result.is_ok(),
            "Failed to subscribe to topic: {:?}",
            subscribe_result.err()
        );

        let mut swarm = comm.p2p.swarm.lock().await;
        let gossipsub = swarm.behaviour_mut().gossipsub_mut();
        let subscriptions: Vec<String> =
            gossipsub.topics().map(|t| t.as_str().to_string()).collect();
        assert!(
            subscriptions.contains(&TEST_TOPIC.to_string()),
            "Should be subscribed to topic"
        );
    }

    #[tokio::test]
    async fn test_publish() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        let connection_result = node1.establish_gossipsub_connection(&mut node2).await;
        assert!(
            connection_result.is_ok(),
            "Gossipsub connection should be established: {:?}",
            connection_result.err()
        );

        let test_message = b"hello world";
        let publish_result = node1.p2p.publish(TEST_TOPIC, test_message).await;

        assert!(
            publish_result.is_ok(),
            "Should publish message successfully, got error: {:?}",
            publish_result.err()
        );
    }

    #[tokio::test]
    async fn test_receive() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        let connection_result = node1.establish_gossipsub_connection(&mut node2).await;
        assert!(
            connection_result.is_ok(),
            "Gossipsub connection should be established: {:?}",
            connection_result.err()
        );

        let is_received = Arc::new(AtomicBool::new(false));
        let is_received_clone = Arc::clone(&is_received);
        let handler = move |message: super::Message| {
            is_received_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                message.topic, TEST_TOPIC,
                "Received message topic should match published topic"
            );
        };

        node2.p2p.receive(handler).await;

        let test_message = b"test receive functionality";
        let publish_result = node1.p2p.publish(TEST_TOPIC, test_message).await;
        assert!(
            publish_result.is_ok(),
            "Should publish message successfully: {:?}",
            publish_result.err()
        );

        tokio::time::sleep(TEST_TIMEOUT_DURATION).await;

        node2.process_events(Duration::from_secs(3)).await;

        assert!(
            is_received.load(std::sync::atomic::Ordering::Relaxed),
            "Should receive message"
        );
    }

    #[tokio::test]
    async fn test_stop_receive() {
        let mut node = TestCommunication::new().await.unwrap();

        assert!(
            !node.p2p.is_receiving().await,
            "receive_task should be None initially"
        );

        let handler = |_: super::Message| {};

        node.p2p.receive(handler).await;
        assert!(
            node.p2p.is_receiving().await,
            "receive_task should be Some after calling start_receive"
        );

        let stop_result = node.p2p.stop_receive();
        assert!(
            stop_result.is_ok(),
            "Should stop receiving messages: {:?}",
            stop_result.err()
        );
    }

    #[tokio::test]
    async fn test_clone() {
        let mut node = TestCommunication::new().await.unwrap();
        let handler = |_: super::Message| {};

        node.p2p.receive(handler).await;

        let cloned = node.p2p.clone(handler).await;
        assert_eq!(node.p2p, cloned, "Cloned P2PCommunication should be equal");
    }
}

#[cfg(test)]
pub mod test_communication {
    use std::time::Duration;

    use libp2p::{
        futures::StreamExt, gossipsub, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId,
        Swarm,
    };
    use tokio::time::timeout;

    use crate::network::p2p_behaviour::{P2PBehaviour, P2PEvent};

    use super::Transport;

    pub const TEST_TIMEOUT_DURATION: Duration = Duration::from_secs(1);
    pub const TEST_TOPIC: &str = "test_topic";

    pub struct TestCommunication {
        pub peer_id: PeerId,
        pub keypair: Keypair,
        pub listen_addr: Multiaddr,
        pub p2p: Transport,
    }

    impl TestCommunication {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;

            let p2p = Transport::new(keypair.clone(), listen_addr.clone(), TEST_TIMEOUT_DURATION)?;

            {
                let mut swarm = p2p
                    .swarm()
                    .await
                    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
                Self::wait_for_listen_addr(&mut swarm).await?;
            }

            let peer_id = PeerId::from_public_key(&keypair.public());

            let listen_addr = {
                let swarm = p2p
                    .swarm()
                    .await
                    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
                Self::get_actual_listen_addr(&swarm)
            };

            Ok(Self {
                peer_id,
                keypair,
                listen_addr,
                p2p,
            })
        }

        fn get_actual_listen_addr(swarm: &Swarm<P2PBehaviour>) -> Multiaddr {
            swarm.listeners().next().cloned().unwrap_or_else(|| {
                panic!("No listen address available");
            })
        }

        async fn wait_for_listen_addr(swarm: &mut Swarm<P2PBehaviour>) -> Result<(), &'static str> {
            timeout(TEST_TIMEOUT_DURATION, async {
                while let Some(event) = swarm.next().await {
                    if let SwarmEvent::NewListenAddr { .. } = event {
                        return Ok(());
                    }
                }
                Err("Timeout waiting for listen address")
            })
            .await
            .map_err(|_| "Timeout waiting for listen address")?
        }

        pub async fn has_peer_in_routing_table(&mut self, peer_id: &PeerId) -> bool {
            let mut swarm = self.p2p.swarm.lock().await;
            swarm.behaviour_mut().kad_mut().kbucket(*peer_id).is_some()
        }

        pub async fn process_events(&mut self, duration: Duration) {
            let start = std::time::Instant::now();
            let mut swarm = self.p2p.swarm.lock().await;
            while start.elapsed() < duration {
                tokio::select! {
                    _ = swarm.select_next_some() => {
                    },
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
        }

        pub async fn establish_gossipsub_connection(
            &mut self,
            other: &mut Self,
        ) -> Result<(), &'static str> {
            self.p2p
                .dial(other.peer_id, other.listen_addr.clone())
                .await
                .map_err(|_| "Failed to dial")?;

            self.p2p
                .subscribe(TEST_TOPIC)
                .await
                .map_err(|_| "Failed to subscribe self")?;
            other
                .p2p
                .subscribe(TEST_TOPIC)
                .await
                .map_err(|_| "Failed to subscribe other")?;

            self.process_events(Duration::from_secs(3)).await;
            other.process_events(Duration::from_secs(3)).await;

            let connection_established = self.check_gossipsub_connection(other).await;

            if !connection_established {
                self.process_events(Duration::from_secs(3)).await;
                other.process_events(Duration::from_secs(3)).await;

                if !self.check_gossipsub_connection(other).await {
                    return Err("Failed to establish Gossipsub connection");
                }
            }

            Ok(())
        }

        async fn check_gossipsub_connection(&mut self, other: &mut Self) -> bool {
            let mut self_swarm = self.p2p.swarm.lock().await;
            let peers_in_mesh1 = self_swarm
                .behaviour_mut()
                .gossipsub_mut()
                .all_peers()
                .count();

            let mut other_swarm = other.p2p.swarm.lock().await;
            let peers_in_mesh2 = other_swarm
                .behaviour_mut()
                .gossipsub_mut()
                .all_peers()
                .count();

            peers_in_mesh1 > 0 && peers_in_mesh2 > 0
        }

        pub async fn wait_for_gossipsub_message(&mut self) -> Option<Vec<u8>> {
            timeout(TEST_TIMEOUT_DURATION, async {
                let mut swarm = self.p2p.swarm.lock().await;
                while let Some(event) = swarm.next().await {
                    if let SwarmEvent::Behaviour(P2PEvent::Gossipsub(gossipsub_event)) = event {
                        if let gossipsub::Event::Message { message, .. } = *gossipsub_event {
                            return Some(message.data);
                        }
                    }
                }
                None
            })
            .await
            .unwrap_or(None)
        }

        pub async fn wait_for_kad_event(&mut self) -> bool {
            timeout(TEST_TIMEOUT_DURATION, async {
                let mut swarm = self.p2p.swarm.lock().await;
                while let Some(event) = swarm.next().await {
                    if let SwarmEvent::Behaviour(_) = event {
                        return true;
                    }
                }
                false
            })
            .await
            .unwrap_or(false)
        }
    }
}
