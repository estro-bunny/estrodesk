use estrodesk_protocol::{Capabilities, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::net::UdpSocket;

pub const DISCOVERY_PORT: u16 = 45822;
const MAX_PACKET_SIZE: usize = 4096;
const DISCOVERY_WINDOW: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub name: String,
    pub address: SocketAddr,
    pub device_id: String,
    pub public_key: String,
    pub capabilities: Capabilities,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("discovery serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryRequest {
    kind: String,
    protocol_version: u16,
    request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryResponse {
    kind: String,
    protocol_version: u16,
    request_id: String,
    device_id: String,
    device_name: String,
    public_key: String,
    tcp_port: u16,
    capabilities: Capabilities,
}

fn request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}-{:x}", std::process::id())
}

pub async fn serve(
    public_key: [u8; 32],
    device_name: String,
    tcp_port: u16,
    capabilities: Capabilities,
) -> Result<(), DiscoveryError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)).await?;
    let public_key = hex::encode(public_key);
    let response_name: String = device_name.chars().filter(|ch| !ch.is_control()).take(64).collect();
    let mut buffer = [0u8; MAX_PACKET_SIZE];

    println!("LAN discovery listening on UDP {DISCOVERY_PORT}");
    loop {
        let (length, source) = socket.recv_from(&mut buffer).await?;
        if length == 0 || length > MAX_PACKET_SIZE {
            continue;
        }

        let Ok(request) = serde_json::from_slice::<DiscoveryRequest>(&buffer[..length]) else {
            continue;
        };
        if request.kind != "estrodesk-discovery-request"
            || request.protocol_version != PROTOCOL_VERSION
            || request.request_id.is_empty()
            || request.request_id.len() > 80
        {
            continue;
        }

        let response = DiscoveryResponse {
            kind: "estrodesk-discovery-response".into(),
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request_id,
            device_id: public_key.clone(),
            device_name: response_name.clone(),
            public_key: public_key.clone(),
            tcp_port,
            capabilities: capabilities.clone(),
        };
        let packet = serde_json::to_vec(&response)?;
        if packet.len() <= MAX_PACKET_SIZE {
            // Discovery is deliberately unauthenticated metadata. The TCP handshake
            // remains the only source of authenticated peer identity.
            if let Err(error) = socket.send_to(&packet, source).await {
                eprintln!("LAN discovery reply failed for {source}: {error}");
            }
        }
    }
}

pub async fn discover() -> Result<Vec<DiscoveredHost>, DiscoveryError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;

    let id = request_id();
    let request = DiscoveryRequest {
        kind: "estrodesk-discovery-request".into(),
        protocol_version: PROTOCOL_VERSION,
        request_id: id.clone(),
    };
    let packet = serde_json::to_vec(&request)?;
    socket
        .send_to(&packet, SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), DISCOVERY_PORT))
        .await?;

    let mut hosts = BTreeMap::<String, DiscoveredHost>::new();
    let mut buffer = [0u8; MAX_PACKET_SIZE];
    let deadline = tokio::time::Instant::now() + DISCOVERY_WINDOW;
    loop {
        let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, source))) = received else {
            break;
        };
        if length == 0 || length > MAX_PACKET_SIZE {
            continue;
        }

        let Ok(response) = serde_json::from_slice::<DiscoveryResponse>(&buffer[..length]) else {
            continue;
        };
        if response.kind != "estrodesk-discovery-response"
            || response.protocol_version != PROTOCOL_VERSION
            || response.request_id != id
            || response.tcp_port == 0
            || response.device_name.is_empty()
            || response.device_name.len() > 256
            || response.public_key.len() != 64
            || !response.public_key.bytes().all(|byte| byte.is_ascii_hexdigit())
            || response.device_id != response.public_key
        {
            continue;
        }

        let address = SocketAddr::new(source.ip(), response.tcp_port);
        let key = format!("{}@{address}", response.device_id);
        let name: String = response.device_name.chars().filter(|ch| !ch.is_control()).take(64).collect();
        hosts.entry(key).or_insert(DiscoveredHost {
            name,
            address,
            device_id: response.device_id,
            public_key: response.public_key,
            capabilities: response.capabilities,
        });
    }

    Ok(hosts.into_values().collect())
}
