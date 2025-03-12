pub mod receive_task;

use std::sync::Arc;

use dashmap::DashMap;
use futures::StreamExt;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade::Version},
    gossipsub::{IdentTopic, MessageId},
    identity::Keypair,
    kad, noise,
    swarm::{self, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, MutexGuard,
    },
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};

use crate::network::{
    behaviour::{Behaviour, P2PEvent},
    message::{gossipsub, request_response, Message},
};

use super::{Error, Result, SubscriptionFilter};

enum ReceiveTaskState {
    Running(JoinHandle<Result<()>>),
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

#[derive(Clone)]
pub struct Libp2pTransport {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    receive_task: Arc<Mutex<ReceiveTaskState>>,
    keypair: Arc<Keypair>,
    receive_timeout: Duration,
    receivers: Arc<DashMap<SubscriptionFilter, Sender<Message>>>,
}

impl Libp2pTransport {
    pub fn new(
        keypair: Keypair,
        listen_addr: Multiaddr,
        receive_timeout: Duration,
    ) -> Result<Self> {
        let transport = Self::create_transport(keypair.clone());
        let behaviour = Behaviour::new(keypair.clone())?;

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
            receivers: Arc::new(DashMap::new()),
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

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .kad_mut()
            .add_address(&peer_id, addr.clone());
        swarm.dial(addr)?;
        Ok(())
    }

    pub async fn subscribe(&self, filter: SubscriptionFilter) -> Receiver<Message> {
        if let SubscriptionFilter::Topic(topic) = &filter {
            // We need to handle error, but for
            // now we just unwrap
            self.subscribe_with_topic(topic).await.unwrap();
        }

        let (tx, rx) = channel(32);
        self.receivers.insert(filter, tx);
        rx
    }

    async fn subscribe_with_topic(&self, topic: &str) -> Result<()> {
        let topic = IdentTopic::new(topic);
        let mut swarm = self.swarm.lock().await;
        swarm.behaviour_mut().gossipsub_mut().subscribe(&topic)?;
        Ok(())
    }

    pub async fn send(&self, message: Message) -> Result<Option<MessageId>> {
        match message {
            Message::Gossipsub(message) => self.send_gossipsub_message(message).await.map(Some),
            Message::RequestResponse(message) => self
                .send_reqeust_response_message(message)
                .await
                .map(|_| None),
        }
    }

    async fn send_gossipsub_message(&self, message: gossipsub::Message) -> Result<MessageId> {
        let topic = IdentTopic::new(&message.topic);
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .gossipsub_mut()
            .publish(topic, message)
            .map_err(|e| e.into())
    }

    async fn send_reqeust_response_message(
        &self,
        message: request_response::Message,
    ) -> Result<()> {
        let target = message.target;
        let mut swarm = self.swarm.lock().await;
        swarm
            .behaviour_mut()
            .request_response_mut()
            .send_request(&target, message);
        Ok(())
    }

    pub async fn receive(&self) {
        let mut task_state = self.receive_task.lock().await;
        if task_state.is_running() {
            return;
        }

        let swarm = self.swarm.clone();
        let receive_timeout = self.receive_timeout;
        let receive_task = Arc::clone(&self.receive_task);
        let receivers = Arc::clone(&self.receivers);

        let task = tokio::spawn(async move {
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

                if let Some(SwarmEvent::Behaviour(event)) = event {
                    match event {
                        P2PEvent::Gossipsub(event) => {
                            Self::handle_gossipsub_event(*event, Arc::clone(&receivers));
                        }
                        P2PEvent::Kad(event) => Self::handle_kad_event(event),
                        P2PEvent::RequestResponse(event) => {
                            Self::handle_request_response_event(event, Arc::clone(&receivers));
                        }
                    }
                }
            }
        });

        *task_state = ReceiveTaskState::Running(task);
    }

    fn handle_gossipsub_event(
        event: libp2p::gossipsub::Event,
        receivers: Arc<DashMap<SubscriptionFilter, Sender<Message>>>,
    ) {
        if let libp2p::gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        } = event
        {
            match gossipsub::Message::try_from(message) {
                Ok(mut msg) => {
                    msg.source = Some(propagation_source);
                    let topic = &msg.topic;
                    let topic_filter = SubscriptionFilter::Topic(topic.clone());

                    let msg = Message::Gossipsub(msg);

                    if let Some(sender) = receivers.get(&topic_filter) {
                        let _ = sender.try_send(msg);
                    }
                }
                Err(e) => eprintln!("Error converting message: {}", e),
            }
        }
    }

    fn handle_kad_event(event: kad::Event) {
        println!("Kademlia event: {:?}", event);
    }

    fn handle_request_response_event(
        event: libp2p::request_response::Event<
            request_response::Message,
            request_response::Message,
        >,
        receivers: Arc<DashMap<SubscriptionFilter, Sender<Message>>>,
    ) {
        if let libp2p::request_response::Event::Message { peer, message, .. } = event {
            let source = peer;
            if let libp2p::request_response::Message::Response { response, .. } = message {
                if response.source != source {
                    eprintln!("Source peer ID does not match message source");
                    return;
                }

                let msg = Message::RequestResponse(response.clone());

                let peer_vec = vec![source];
                let peer_filter = SubscriptionFilter::Peer(peer_vec);

                if let Some(sender) = receivers.get(&peer_filter) {
                    let _ = sender.try_send(msg);
                }
            }
        }
    }

    pub fn stop_receive(&self) -> Result<()> {
        if let Ok(mut task_state) = self.receive_task.try_lock() {
            task_state.stop();
        }
        Ok(())
    }

    pub async fn swarm(&self) -> Result<MutexGuard<'_, Swarm<Behaviour>>> {
        self.get_swarm_lock().await
    }

    async fn get_swarm_lock(&self) -> Result<MutexGuard<'_, Swarm<Behaviour>>> {
        match timeout(Duration::from_secs(5), self.swarm.lock()).await {
            Ok(guard) => Ok(guard),
            Err(_) => Err(Error::LockError),
        }
    }

    pub async fn is_receiving(&self) -> bool {
        self.receive_task.lock().await.is_running()
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
    use crate::network::{
        message,
        transport::{
            libp2p_transport::test_transport::{create_test_payload, TestTransport, TEST_TOPIC},
            SubscriptionFilter,
        },
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_new() {
        let tt = TestTransport::new().await.unwrap();
        let addr = tt.listen_addr;
        assert!(addr.to_string().contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn test_dial() {
        let mut t1 = TestTransport::new().await.unwrap();
        let t2 = TestTransport::new().await.unwrap();
        t1.p2p
            .dial(t2.peer_id, t2.listen_addr.clone())
            .await
            .unwrap();
        t1.process_events(Duration::from_secs(1)).await;
        assert!(t1.has_peer_in_routing_table(&t2.peer_id).await);
    }

    #[tokio::test]
    async fn test_subscribe() {
        let t1 = TestTransport::new().await.unwrap();
        let filter = SubscriptionFilter::Topic(TEST_TOPIC.to_string());
        let rx = t1.p2p.subscribe(filter).await;
        assert!(rx.capacity() == 32);
    }

    #[tokio::test]
    async fn test_send_gossipsub_message() {
        let mut t1 = TestTransport::new().await.unwrap();
        let mut t2 = TestTransport::new().await.unwrap();
        t1.establish_gossipsub_connection(&mut t2).await.unwrap();
        let payload = create_test_payload();
        let msg = message::gossipsub::Message::new(TEST_TOPIC, payload);
        let transport_msg = message::Message::Gossipsub(msg);
        t1.p2p.send(transport_msg).await.unwrap();
        let received = t2.wait_for_gossipsub_message().await;
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_send_request_response_message() {
        let mut t1 = TestTransport::new().await.unwrap();
        let t2 = TestTransport::new().await.unwrap();
        let payload = create_test_payload();
        let req_msg = message::request_response::Message::new(t1.peer_id, t2.peer_id, payload);
        let transport_msg = message::Message::RequestResponse(req_msg);
        t1.p2p.send(transport_msg).await.unwrap();
        t1.process_events(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn test_receive() {
        let t1 = TestTransport::new().await.unwrap();
        t1.p2p.receive().await;
        assert!(t1.p2p.is_receiving().await);
    }

    #[tokio::test]
    async fn test_clone() {
        let t1 = TestTransport::new().await.unwrap();
        let t2 = t1.p2p.clone();

        assert_eq!(t1.p2p, t2);
    }
}

#[cfg(test)]
pub mod test_transport {
    use std::time::Duration;

    use libp2p::{
        futures::StreamExt, gossipsub, identity::Keypair, swarm::SwarmEvent, Multiaddr, PeerId,
        Swarm,
    };
    use tokio::time::timeout;

    use crate::network::{
        behaviour::{Behaviour, P2PEvent},
        message::Payload,
    };

    use super::Libp2pTransport;

    pub const TEST_TIMEOUT_DURATION: Duration = Duration::from_secs(1);
    pub const TEST_TOPIC: &str = "test_topic";

    pub fn create_test_payload() -> Payload {
        Payload::RawData {
            data: b"test".to_vec(),
        }
    }

    pub struct TestTransport {
        pub peer_id: PeerId,
        pub keypair: Keypair,
        pub listen_addr: Multiaddr,
        pub p2p: Libp2pTransport,
    }

    impl TestTransport {
        pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let keypair = Keypair::generate_ed25519();
            let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse()?;

            let p2p =
                Libp2pTransport::new(keypair.clone(), listen_addr.clone(), TEST_TIMEOUT_DURATION)?;

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

        fn get_actual_listen_addr(swarm: &Swarm<Behaviour>) -> Multiaddr {
            swarm.listeners().next().cloned().unwrap_or_else(|| {
                panic!("No listen address available");
            })
        }

        async fn wait_for_listen_addr(swarm: &mut Swarm<Behaviour>) -> Result<(), &'static str> {
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
                .subscribe_with_topic(TEST_TOPIC)
                .await
                .map_err(|_| "Failed to subscribe self")?;
            other
                .p2p
                .subscribe_with_topic(TEST_TOPIC)
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
