use std::{io, sync::Arc, time};

use crossbeam_channel::{unbounded, Receiver, Sender};
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageId},
    identity::Keypair,
    noise,
    swarm::{self, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use thiserror::Error;
use tokio::{sync::MutexGuard, task::JoinHandle};

use super::p2p_behaviour::{self, P2PBehaviour, P2PEvent};

#[derive(Debug, Error)]
pub enum P2PCommunicationError {
    #[error("Transport Error: {0}")]
    Transport(#[from] libp2p::TransportError<io::Error>),
    #[error("Dial Error: {0}")]
    Dial(#[from] swarm::DialError),
    #[error("Gossipsub Error: {0}")]
    Gossipsub(String),
    #[error("Subscribe Error: {0}")]
    Subscribe(#[from] gossipsub::SubscriptionError),
    #[error("Publish Error: {0}")]
    Publish(#[from] gossipsub::PublishError),
    #[error("System Time Error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("Crossbeam Channel Error: {0}")]
    CrossbeamChannel(String),
    #[error("P2P Behaviour Error: {0}")]
    P2PBehaviour(#[from] p2p_behaviour::P2PBehaviourError),
    #[error("Task Join Error: {0}")]
    TaskJoin(String),
}

impl From<crossbeam_channel::SendError<P2PMessage>> for P2PCommunicationError {
    fn from(err: crossbeam_channel::SendError<P2PMessage>) -> Self {
        P2PCommunicationError::CrossbeamChannel(err.to_string())
    }
}

impl From<tokio::task::JoinError> for P2PCommunicationError {
    fn from(err: tokio::task::JoinError) -> Self {
        P2PCommunicationError::TaskJoin(err.to_string())
    }
}

type P2PCommunicationResult<T> = Result<T, P2PCommunicationError>;

pub struct P2PCommunication {
    swarm: Arc<tokio::sync::Mutex<Swarm<P2PBehaviour>>>,
    message_sender: Sender<P2PMessage>,
    message_receiver: Arc<Receiver<P2PMessage>>,
    receive_task: Option<JoinHandle<P2PCommunicationResult<()>>>,
}

impl std::fmt::Debug for P2PCommunication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PCommunication")
            .field("message_sender", &self.message_sender)
            .field("message_receiver", &self.message_receiver)
            .field("receive_task", &self.receive_task.is_some())
            .field("swarm", &"Arc<Mutex<Swarm<P2PBehaviour>>>") // We just want to show that the field exists, not its value
            .finish()
    }
}

impl PartialEq for P2PCommunication {
    fn eq(&self, other: &Self) -> bool {
        let self_peer_id = match self.swarm.try_lock() {
            Ok(swarm) => *swarm.local_peer_id(),
            Err(_) => return false, // If we can't lock, consider them not equal
        };

        let other_peer_id = match other.swarm.try_lock() {
            Ok(swarm) => *swarm.local_peer_id(),
            Err(_) => return false, // If we can't lock, consider them
        };

        self_peer_id == other_peer_id
    }
}

impl P2PCommunication {
    pub fn new(keypair: Keypair, listen_addr: Multiaddr) -> P2PCommunicationResult<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = P2PBehaviour::new(keypair.clone())?;

        let mut swarm = Swarm::new(
            transport,
            behaviour,
            PeerId::from_public_key(&keypair.public()),
            swarm::Config::with_tokio_executor(),
        );
        swarm.listen_on(listen_addr)?;

        let (message_sender, message_receiver) = unbounded();

        Ok(Self {
            swarm: Arc::new(tokio::sync::Mutex::new(swarm)),
            message_sender,
            message_receiver: Arc::new(message_receiver),
            receive_task: None,
        })
    }

    fn create_transport(keypair: Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        tcp::tokio::Transport::default()
            .upgrade(Version::V1)
            .authenticate(noise::Config::new(&keypair).unwrap())
            .multiplex(yamux::Config::default())
            .boxed()
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> P2PCommunicationResult<()> {
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.dial(addr)?;

        Ok(())
    }

    pub async fn subscribe(&self, topic: &str) -> P2PCommunicationResult<()> {
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().gossipsub_mut().subscribe(&topic)?;
        Ok(())
    }

    pub async fn publish(
        &self,
        topic: &str,
        data: impl Into<Vec<u8>>,
    ) -> P2PCommunicationResult<()> {
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().gossipsub_mut().publish(topic, data)?;
        Ok(())
    }

    pub async fn start_receive(&mut self, sleep_duration: tokio::time::Duration) {
        if self.receive_task.is_some() {
            return;
        }

        let swarm = self.swarm.clone();
        let message_sender = self.message_sender.clone();

        let task = tokio::spawn(async move {
            loop {
                let event = {
                    let mut swarm_lock = swarm.lock().await;
                    tokio::select! {
                        event = swarm_lock.select_next_some() => Some(event),
                        _ = tokio::time::sleep(sleep_duration) => None,
                    }
                };

                if let Some(SwarmEvent::Behaviour(P2PEvent::Gossipsub(event))) = event {
                    if let gossipsub::Event::Message {
                        message_id,
                        propagation_source,
                        message,
                    } = *event
                    {
                        let timestamp = time::SystemTime::now()
                            .duration_since(time::UNIX_EPOCH)?
                            .as_secs();

                        let p2p_message = P2PMessage {
                            message_id,
                            source: propagation_source,
                            topic: message.topic.into_string(),
                            data: message.data,
                            timestamp,
                        };

                        message_sender.send(p2p_message)?;
                    }
                }
            }
        });

        self.receive_task = Some(task);
    }

    pub fn stop_receive(&mut self) -> P2PCommunicationResult<()> {
        if let Some(task) = self.receive_task.take() {
            task.abort();
        }

        Ok(())
    }

    pub fn message_receiver(&self) -> Arc<Receiver<P2PMessage>> {
        self.message_receiver.clone()
    }

    pub async fn swarm(&self) -> MutexGuard<'_, Swarm<P2PBehaviour>> {
        self.swarm.lock().await
    }

    pub fn is_receiving(&self) -> bool {
        self.receive_task.is_some()
    }

    pub async fn clone(&self, sleep_duration: tokio::time::Duration) -> Self {
        let swarm = Arc::clone(&self.swarm);
        let (message_sender, message_receiver) = unbounded();
        let message_receiver = Arc::new(message_receiver);

        let mut cloned = Self {
            swarm,
            message_sender,
            message_receiver,
            receive_task: None,
        };

        if self.is_receiving() {
            cloned.start_receive(sleep_duration).await;
        }

        cloned
    }
}

#[derive(Debug)]
pub struct P2PMessage {
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::network::p2p_communication::test_communication::{TestCommunication, TEST_TOPIC};

    const TIMEOUT_DURATION: Duration = Duration::from_secs(5);

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

        let received_message = node2.wait_for_gossipsub_message().await;

        assert!(
            received_message.is_some(),
            "Should receive the published message"
        );

        assert_eq!(
            received_message.unwrap(),
            test_message.to_vec(),
            "Received message should match published message"
        );
    }

    #[tokio::test]
    async fn test_start_receive() {
        let mut node1 = TestCommunication::new().await.unwrap();
        let mut node2 = TestCommunication::new().await.unwrap();

        let connection_result = node1.establish_gossipsub_connection(&mut node2).await;
        assert!(
            connection_result.is_ok(),
            "Gossipsub connection should be established: {:?}",
            connection_result.err()
        );

        let receiver = node2.p2p.message_receiver();

        let receive_handle = tokio::spawn(async move {
            node2
                .p2p
                .start_receive(tokio::time::Duration::from_millis(10))
                .await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let test_message = b"test receive functionality";
        let publish_result = node1.p2p.publish(TEST_TOPIC, test_message).await;
        assert!(
            publish_result.is_ok(),
            "Should publish message successfully: {:?}",
            publish_result.err()
        );

        let received_message = tokio::task::spawn_blocking(move || {
            receiver
                .recv_timeout(TIMEOUT_DURATION)
                .expect("Failed to receive message or timeout")
        })
        .await
        .expect("Failed to join the receive task");

        timeout(Duration::from_secs(1), receive_handle)
            .await
            .expect("Timeout waiting for receive task to end")
            .expect("Receive task panicked");

        assert_eq!(
            received_message.data,
            test_message.to_vec(),
            "Received message data should match published message"
        );
        assert_eq!(
            received_message.topic, TEST_TOPIC,
            "Received message topic should match published topic"
        );
    }

    #[tokio::test]
    async fn test_stop_receive() {
        let mut node = TestCommunication::new().await.unwrap();

        assert!(
            !node.p2p.is_receiving(),
            "receive_task should be None initially"
        );

        node.p2p
            .start_receive(tokio::time::Duration::from_millis(10))
            .await;
        assert!(
            node.p2p.is_receiving(),
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
        const SLEEP_DURATION: Duration = Duration::from_millis(10);

        let mut node = TestCommunication::new().await.unwrap();
        node.p2p
            .start_receive(tokio::time::Duration::from_millis(10))
            .await;

        let cloned = node.p2p.clone(SLEEP_DURATION).await;

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

    use super::P2PCommunication;

    pub const TEST_TIMEOUT_DURATION: Duration = Duration::from_secs(5);
    pub const TEST_TOPIC: &str = "test_topic";

    pub struct TestCommunication {
        pub peer_id: PeerId,
        pub keypair: Keypair,
        pub listen_addr: Multiaddr,
        pub p2p: P2PCommunication,
    }

    impl TestCommunication {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;

            let p2p = P2PCommunication::new(keypair.clone(), listen_addr.clone())?;

            {
                let mut swarm = p2p.swarm.lock().await;
                Self::wait_for_listen_addr(&mut swarm).await?;
            }

            let peer_id = PeerId::from_public_key(&keypair.public());

            let listen_addr = {
                let swarm = p2p.swarm.lock().await;
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
