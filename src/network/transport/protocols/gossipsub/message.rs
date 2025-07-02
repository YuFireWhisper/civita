use libp2p::{
    gossipsub::{Event, MessageId},
    PeerId,
};
use log::error;
use thiserror::Error;

use crate::{
    network::transport::{dispatcher::Keyed, protocols::gossipsub::Payload},
    traits::{serializable, Serializable},
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Source field is none")]
    MissingSource,

    #[error("Event is not a message")]
    NotMessageEvent,

    #[error("{0}")]
    Serializable(#[from] serializable::Error),
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone)]
#[derive(Debug)]
#[derive(Eq, PartialEq)]
pub struct Message {
    pub message_id: MessageId,
    pub source: PeerId,
    pub topic: String,
    pub payload: Payload,
}

impl Message {
    pub fn try_from_gossipsub_event(event: Event) -> Result<Self> {
        Self::try_from(event)
    }
}

impl Keyed<String> for Message {
    fn key(&self) -> &String {
        &self.topic
    }
}

impl TryFrom<libp2p::gossipsub::Event> for Message {
    type Error = Error;

    fn try_from(event: Event) -> Result<Self> {
        if let Event::Message {
            message_id,
            message,
            ..
        } = event
        {
            let source = message.source.ok_or(Error::MissingSource)?;
            let topic = message.topic.into_string();
            let payload = Payload::from_slice(message.data.as_slice())?;

            Ok(Self {
                message_id,
                source,
                topic,
                payload,
            })
        } else {
            Err(Error::NotMessageEvent)
        }
    }
}

impl Serializable for Message {
    fn serialized_size(&self) -> usize {
        self.message_id.serialized_size()
            + self.source.serialized_size()
            + self.topic.serialized_size()
            + self.payload.serialized_size()
    }

    fn from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, serializable::Error> {
        Ok(Self {
            message_id: MessageId::from_reader(reader)?,
            source: PeerId::from_reader(reader)?,
            topic: String::from_reader(reader)?,
            payload: Payload::from_reader(reader)?,
        })
    }

    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> Result<(), serializable::Error> {
        self.message_id.to_writer(writer)?;
        self.source.to_writer(writer)?;
        self.topic.to_writer(writer)?;
        self.payload.to_writer(writer)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use libp2p::{gossipsub::MessageId, PeerId};

    use crate::{
        network::transport::protocols::gossipsub::{Message, Payload},
        traits::Serializable,
    };

    #[test]
    fn success_convert_with_vec() {
        const MESSAGE_ID: &[u8] = &[1, 2, 3, 4, 5];
        const TOPIC: &str = "test-topic";
        const PAYLOAD: &[u8] = &[1, 2, 3, 4, 5];

        let msg = Message {
            message_id: MessageId::from(MESSAGE_ID),
            source: PeerId::random(),
            topic: TOPIC.to_string(),
            payload: Payload::Raw(PAYLOAD.to_vec()),
        };

        let msg_vec = msg.to_vec().unwrap();
        let msg_from_vec = Message::from_slice(&msg_vec).unwrap();

        assert_eq!(msg, msg_from_vec);
    }
}
