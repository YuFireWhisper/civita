use crate::network::transport::Transport;

pub struct Classic<T: Transport> {
    transport: T,
}

impl<T: Transport> Classic<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

#[cfg(test)]
mod tests {
    use mockall::mock;

    use crate::crypto::dkg::classic::Classic;

    mock! {
        pub Transport {}
        impl crate::network::transport::Transport for Transport {
            fn dial(
                &self,
                peer_id: libp2p::PeerId,
                addr: libp2p::Multiaddr,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::network::transport::Error>> + Send>>;
            fn listen(
                &self,
                filter: crate::network::transport::Listener,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<tokio::sync::mpsc::Receiver<crate::network::transport::libp2p_transport::message::Message>, crate::network::transport::Error>> + Send>>;
            fn publish<'a>(
                &'a self,
                topic: &'a str,
                payload: crate::network::transport::libp2p_transport::protocols::gossipsub::Payload,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<libp2p::gossipsub::MessageId, crate::network::transport::Error>> + Send>>;
            fn request<'a>(
                &'a self,
                peer_id: libp2p::PeerId,
                payload: crate::network::transport::libp2p_transport::protocols::request_response::payload::Request,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), crate::network::transport::Error>> + Send>>;
        }
    }

    #[test]
    fn create() {
        let transport = MockTransport::new();

        let result = Classic::new(transport);

        assert!(matches!(result, Classic { .. }));
    }
}
