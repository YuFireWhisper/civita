use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAcceptance},
    request_response::{self},
    swarm::SwarmEvent,
    Swarm,
};
use tokio::sync::mpsc;

use crate::{
    event::Event,
    network::{
        behaviour::{Behaviour, BehaviourEvent},
        transport::{Command, Request, Response},
    },
    traits,
    ty::Atom,
};

pub struct Inner<T: traits::Config> {
    swarm: Swarm<Behaviour<T>>,
    rx: mpsc::Receiver<Command<T>>,
    tx: mpsc::Sender<Event<T>>,
    topic: IdentTopic,
}

impl<T: traits::Config> Inner<T> {
    pub fn spawn(
        swarm: Swarm<Behaviour<T>>,
        rx: mpsc::Receiver<Command<T>>,
        tx: mpsc::Sender<Event<T>>,
    ) {
        let topic = IdentTopic::new(0u8.to_string());

        let mut inner = Self {
            swarm,
            rx,
            tx,
            topic,
        };

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = inner.swarm.select_next_some() => {
                        inner.handle_event(event).await;
                    },
                    Some(cmd) = inner.rx.recv() => {
                        if !inner.handle_command(cmd) {
                            break;
                        }
                    },
                };

                tokio::task::yield_now().await;
            }
        });
    }

    async fn handle_event(&mut self, event: SwarmEvent<BehaviourEvent<T>>) {
        match event {
            SwarmEvent::Behaviour(event) => match event {
                BehaviourEvent::Gossipsub(event) => {
                    self.handle_gossipsub_event(event).await;
                }
                BehaviourEvent::RequestResponse(event) => {
                    self.handle_request_response_event(event).await;
                }
                BehaviourEvent::Kad(_) => {
                    // Do nothing
                }
            },
            _ => {
                // Handle other swarm events if necessary
            }
        }
    }

    async fn handle_gossipsub_event(&mut self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => match Atom::from_bytes(&message.data) {
                Ok(atom) => {
                    let event = Event::Gossipsub(message_id, propagation_source, Box::new(atom));
                    let _ = self.tx.send(event).await;
                }
                Err(_) => {
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            MessageAcceptance::Reject,
                        );
                }
            },
            _ => {
                // Handle other gossipsub events if necessary
            }
        }
    }

    async fn handle_request_response_event(
        &mut self,
        event: request_response::Event<Request, Response<T>>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                libp2p::request_response::Message::Request {
                    request, channel, ..
                } => {
                    let event = Event::Request(request, peer, channel);
                    let _ = self.tx.send(event).await;
                }
                libp2p::request_response::Message::Response { response, .. } => {
                    let event = Event::Response(response, peer);
                    let _ = self.tx.send(event).await;
                }
            },
            request_response::Event::OutboundFailure { peer, error, .. } => {
                log::error!("Outbound request to {peer} failed: {error}");
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                log::error!("Inbound request from {peer} failed: {error}");
            }
            request_response::Event::ResponseSent { peer, .. } => {
                log::info!("Response sent to {peer}");
            }
        }
    }

    fn handle_command(&mut self, command: Command<T>) -> bool {
        match command {
            Command::Disconnect(peer_id) => {
                self.swarm.behaviour_mut().kad.remove_peer(&peer_id);
                let _ = self.swarm.disconnect_peer_id(peer_id);
                true
            }
            Command::Publish(data) => {
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(self.topic.hash(), data)
                {
                    log::error!("{e}");
                }
                true
            }
            Command::Report(msg_id, peer_id, acceptance) => {
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(&msg_id, &peer_id, acceptance);
                true
            }
            Command::SendRequest(req, peer) => {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer, req);
                true
            }
            Command::SendResponse(resp, channel) => {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, resp);
                true
            }
            Command::Stop => false,
        }
    }
}
