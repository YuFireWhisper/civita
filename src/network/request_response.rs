use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::request_response;
use serde::{Deserialize, Serialize};
use std::{future::Future, io, pin::Pin};
use thiserror::Error;

use super::message::MessagePayload;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("{0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("{0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub request_id: String,
    pub payload: MessagePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub request_id: String,
    pub result: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub struct Codec;

impl Codec {
    async fn read_data<T: AsyncRead + Unpin>(io: &mut T) -> Result<Vec<u8>, io::Error> {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut buffer = vec![0u8; len];
        io.read_exact(&mut buffer).await?;
        Ok(buffer)
    }

    async fn write_data<T: AsyncWrite + Unpin>(io: &mut T, data: &[u8]) -> Result<(), io::Error> {
        let len = data.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(data).await?;
        io.flush().await
    }
}

#[async_trait]
impl request_response::Codec for Codec {
    type Protocol = &'static str;
    type Request = Request;
    type Response = Response;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Request, io::Error>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
    {
        Box::pin(async move {
            let buffer = Self::read_data(io).await?;
            serde_json::from_slice(&buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, io::Error>> + Send + 'async_trait>>
    where
        T: AsyncRead + Unpin + Send + 'async_trait,
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
    {
        Box::pin(async move {
            let buffer = Self::read_data(io).await?;
            serde_json::from_slice(&buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&req)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            Self::write_data(io, &data).await
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        res: Self::Response,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + 'async_trait>>
    where
        T: AsyncWrite + Unpin + Send + 'async_trait,
        Self: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
    {
        Box::pin(async move {
            let data = serde_json::to_vec(&res)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            Self::write_data(io, &data).await
        })
    }
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    use crate::network::{
        message::MessagePayload,
        request_response::{Codec, Response},
    };

    use super::Request;

    fn create_request() -> Request {
        Request {
            request_id: "test_id".to_string(),
            payload: MessagePayload::RawData {
                data: "test_data".as_bytes().to_vec(),
            },
        }
    }

    #[tokio::test]
    async fn test_write_and_read_request() {
        let request = create_request();

        let mut write_buf = Vec::new();
        let mut codec = Codec;

        codec
            .write_request(&"test_protocol", &mut write_buf, request.clone())
            .await
            .expect("Failed to write request");

        let mut read_buf = Cursor::new(write_buf);
        let read_request = codec
            .read_request(&"test_protocol", &mut read_buf)
            .await
            .expect("Failed to read request");

        assert_eq!(request.request_id, read_request.request_id);
    }

    #[tokio::test]
    async fn test_write_and_read_response() {
        let response = Response {
            request_id: "test_id".to_string(),
            result: vec![1, 2, 3, 4],
        };

        let mut write_buf = Vec::new();
        let mut codec = Codec;

        codec
            .write_response(&"test_protocol", &mut write_buf, response.clone())
            .await
            .expect("Failed to write response");

        let mut read_buf = Cursor::new(write_buf);
        let read_response = codec
            .read_response(&"test_protocol", &mut read_buf)
            .await
            .expect("Failed to read response");

        assert_eq!(response.request_id, read_response.request_id);
        assert_eq!(response.result, read_response.result);
    }
}
