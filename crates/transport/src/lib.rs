use estrodesk_crypto::{CryptoError, SessionCipher};
use estrodesk_protocol::Envelope;
use serde_json;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 1024 * 1024;
const SEQUENCE_SIZE: usize = 8;
const CIPHERTEXT_OVERHEAD: usize = 16;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("frame exceeds maximum size")]
    FrameTooLarge,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] serde_json::Error),
    #[error("cryptographic failure: {0}")]
    Crypto(#[from] CryptoError),
    #[error("replayed or out-of-order frame: expected {expected}, received {received}")]
    Replay { expected: u64, received: u64 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

fn nonce(direction: u32, sequence: u64) -> [u8; 12] {
    let mut value = [0u8; 12];
    value[..4].copy_from_slice(&direction.to_be_bytes());
    value[4..].copy_from_slice(&sequence.to_be_bytes());
    value
}

fn aad(direction: u32, sequence: u64) -> [u8; 12] {
    nonce(direction, sequence)
}

pub async fn send<W>(writer: &mut W, envelope: &Envelope) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(envelope)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(TransportError::FrameTooLarge);
    }

    let length = u32::try_from(payload.len()).map_err(|_| TransportError::FrameTooLarge)?;
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
    envelope.validate().map_err(|error| serde_json::Error::io(
        std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
    ))?;
    Ok(envelope)
}

pub struct SecureChannel {
    send_cipher: SessionCipher,
    receive_cipher: SessionCipher,
    send_sequence: u64,
    receive_sequence: u64,
    send_direction: u32,
    receive_direction: u32,
}

impl SecureChannel {
    pub fn controller(send_key: &[u8; 32], receive_key: &[u8; 32]) -> Self {
        Self::new(send_key, receive_key, 0x45534354, 0x45534854)
    }

    pub fn host(send_key: &[u8; 32], receive_key: &[u8; 32]) -> Self {
        Self::new(send_key, receive_key, 0x45534854, 0x45534354)
    }

    fn new(
        send_key: &[u8; 32],
        receive_key: &[u8; 32],
        send_direction: u32,
        receive_direction: u32,
    ) -> Self {
        Self {
            send_cipher: SessionCipher::new(send_key),
            receive_cipher: SessionCipher::new(receive_key),
            send_sequence: 0,
            receive_sequence: 0,
            send_direction,
            receive_direction,
        }
    }

    pub async fn send<W>(
        &mut self,
        writer: &mut W,
        envelope: &Envelope,
    ) -> Result<(), TransportError>
    where
        W: AsyncWrite + Unpin,
    {
        let plaintext = serde_json::to_vec(envelope)?;
        let sequence = self.send_sequence;
        let nonce = nonce(self.send_direction, sequence);
        let ciphertext = self.send_cipher.encrypt_with_aad(&nonce, &plaintext, &aad(self.send_direction, sequence))?;

        let frame_size = SEQUENCE_SIZE + ciphertext.len();
        if frame_size > MAX_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge);
        }

        let length = u32::try_from(frame_size).map_err(|_| TransportError::FrameTooLarge)?;
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(&sequence.to_be_bytes()).await?;
        writer.write_all(&ciphertext).await?;
        writer.flush().await?;

        self.send_sequence = self.send_sequence.checked_add(1).ok_or(TransportError::Replay {
            expected: u64::MAX,
            received: u64::MAX,
        })?;
        Ok(())
    }

    pub async fn receive<R>(&mut self, reader: &mut R) -> Result<Envelope, TransportError>
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
        if length < SEQUENCE_SIZE + CIPHERTEXT_OVERHEAD || length > MAX_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge);
        }

        let mut sequence_bytes = [0u8; SEQUENCE_SIZE];
        reader.read_exact(&mut sequence_bytes).await?;
        let sequence = u64::from_be_bytes(sequence_bytes);

        if sequence != self.receive_sequence {
            return Err(TransportError::Replay { expected: self.receive_sequence, received: sequence });
        }

        let mut ciphertext = vec![0u8; length - SEQUENCE_SIZE];
        reader.read_exact(&mut ciphertext).await?;

        let nonce = nonce(self.receive_direction, sequence);
        let plaintext = self.receive_cipher.decrypt_with_aad(
            &nonce,
            &ciphertext,
            &aad(self.receive_direction, sequence),
        )?;

        let envelope = serde_json::from_slice(&plaintext)?;
        envelope.validate().map_err(|error| serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        ))?;

        self.receive_sequence = self.receive_sequence.checked_add(1).ok_or(TransportError::Replay {
            expected: u64::MAX,
            received: u64::MAX,
        })?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use estrodesk_crypto::{derive_directional_keys, transcript_hash, EphemeralKeyExchange};
    use estrodesk_protocol::{Envelope, Message};
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn sends_and_receives_an_envelope() {
        let (mut a, mut b) = duplex(4096);
        let original = Envelope::new(Message::Ping { nonce: 42 });
        send(&mut a, &original).await.unwrap();
        assert_eq!(receive(&mut b).await.unwrap(), original);
    }

    #[tokio::test]
    async fn rejects_oversized_frames() {
        let (mut a, _b) = duplex(4096);
        let oversized = Envelope::new(Message::Hello(estrodesk_protocol::Hello {
            device_id: "x".repeat(MAX_FRAME_SIZE + 1),
            device_name: "test".into(),
            capabilities: Default::default(),
        }));
        assert!(matches!(send(&mut a, &oversized).await, Err(TransportError::FrameTooLarge)));
    }

    fn channels() -> (SecureChannel, SecureChannel) {
        let controller = EphemeralKeyExchange::generate();
        let host = EphemeralKeyExchange::generate();
        let shared = controller.derive_shared_secret(&host.public_key_bytes());
        let transcript = transcript_hash(
            &[1; 32], &[2; 32],
            &controller.public_key_bytes(), &host.public_key_bytes(),
        );
        let (c2h, h2c) = derive_directional_keys(&shared, &transcript).unwrap();
        (
            SecureChannel::controller(&c2h, &h2c),
            SecureChannel::host(&h2c, &c2h),
        )
    }

    #[tokio::test]
    async fn secure_channel_round_trips_and_rejects_replay() {
        let (mut controller, mut host) = channels();
        let (mut wire_a, mut wire_b) = duplex(4096);
        let message = Envelope::new(Message::Ping { nonce: 7 });

        controller.send(&mut wire_a, &message).await.unwrap();
        assert_eq!(host.receive(&mut wire_b).await.unwrap(), message);

        controller.send(&mut wire_a, &message).await.unwrap();
        assert_eq!(host.receive(&mut wire_b).await.unwrap(), message);
    }

    #[tokio::test]
    async fn secure_channel_rejects_tampered_ciphertext() {
        let (mut controller, mut host) = channels();
        let (mut wire_a, mut wire_b) = duplex(4096);
        let message = Envelope::new(Message::Ping { nonce: 99 });

        controller.send(&mut wire_a, &message).await.unwrap();

        let mut length = [0u8; 4];
        wire_b.read_exact(&mut length).await.unwrap();
        let frame_len = u32::from_be_bytes(length) as usize;
        let mut frame = vec![0u8; frame_len];
        wire_b.read_exact(&mut frame).await.unwrap();
        frame[SEQUENCE_SIZE] ^= 1;

        wire_a.write_all(&length).await.unwrap();
        wire_a.write_all(&frame).await.unwrap();
        drop(wire_b);

        let result = host.receive(&mut wire_a).await;
        assert!(matches!(result, Err(TransportError::Crypto(_))));
    }
}
