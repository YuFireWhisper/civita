pub mod gossipsub;
pub mod request_response;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Message {
    Gossipsub(gossipsub::Message),
    RequestResponse(request_response::Message),
}
