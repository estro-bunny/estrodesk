use estrodesk_protocol::Envelope;
use serde_json;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("frame exceeds maximum size")]
    FrameTooLarge,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn send<W>(writer: &mut W, envelope: &Envelope) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(envelope)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(TransportError::FrameTooLarge);
    }

    let length = u32::try_from(payload.len())
        .map_err(|_| TransportError::FrameTooLarge)?;

    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;

    Ok(())
}

pub async fn receive<R>(reader: &mut R) -> Result<Envelope, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0u8; 4];

    match reader.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::ConnectionClosed);
        }
        Err(error) => return Err(TransportError::Io(error)),
    }

    let length = u32::from_be_bytes(length_bytes) as usize;

    if length > MAX_FRAME_SIZE {
        return Err(TransportError::FrameTooLarge);
    }

    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    let envelope = serde_json::from_slice(&payload)?;
    envelope.validate()
        .map_err(|error| serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )))?;

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use estrodesk_protocol::{Envelope, Message};
    use tokio::io::duplex;

    #[tokio::test]
    async fn sends_and_receives_an_envelope() {
        let (mut a, mut b) = duplex(4096);
        let original = Envelope::new(Message::Ping { nonce: 42 });

        send(&mut a, &original).await.unwrap();
        let received = receive(&mut b).await.unwrap();

        assert_eq!(received, original);
    }

    #[tokio::test]
    async fn rejects_oversized_frames() {
        let (mut a, _b) = duplex(4096);
        let oversized = Envelope::new(Message::Hello(
            estrodesk_protocol::Hello {
                device_id: "x".repeat(MAX_FRAME_SIZE + 1),
                device_name: "test".into(),
                capabilities: Default::default(),
            },
        ));

        assert!(matches!(
            send(&mut a, &oversized).await,
            Err(TransportError::FrameTooLarge)
        ));
    }
}
