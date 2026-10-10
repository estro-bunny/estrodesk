mod identity;

use estrodesk_crypto::DeviceIdentity;
use estrodesk_protocol::{AuthenticationAck, Capabilities, Envelope, Message};
use estrodesk_session::{load_trust_store, save_trust_store, ControllerHandshake, HostHandshake, TrustStatus, TrustStore};
use estrodesk_transport::{receive, send, SecureChannel};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const DEFAULT_PORT: u16 = 45821;

fn capabilities() -> Capabilities {
    Capabilities { screen: true, input: true, clipboard: true, files: false, audio: false }
}

fn fingerprint(public_key: &[u8; 32]) -> String {
    public_key.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>()
        .chunks(4).map(|chunk| chunk.join("")).collect::<Vec<_>>().join(":")
}

fn approve(label: &str, public_key: &[u8; 32]) -> bool {
    println!("\nEstroDesk trust request");
    println!("Peer: {label}");
    println!("Public-key fingerprint: {}", fingerprint(public_key));
    print!("Trust this device permanently? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() { return false; }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn session_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or_default();
    format!("session-{nanos:x}")
}

fn data_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(value) = env::var("ESTRODESK_DATA_DIR") { return Ok(PathBuf::from(value)); }
    #[cfg(windows)]
    if let Ok(value) = env::var("APPDATA") { return Ok(PathBuf::from(value).join("EstroDesk")); }
    #[cfg(not(windows))]
    if let Ok(value) = env::var("XDG_DATA_HOME") { return Ok(PathBuf::from(value).join("estrodesk")); }
    Err("set ESTRODESK_DATA_DIR or the platform data-directory variable".into())
}

fn load_identity() -> Result<DeviceIdentity, Box<dyn std::error::Error>> {
    let dir = data_dir()?;
    let identity = identity::load_or_create(&dir)?;
    println!("Identity file: {}", identity::identity_path(&dir).display());
    Ok(identity)
}

fn load_trust() -> Result<TrustStore, Box<dyn std::error::Error>> {
    Ok(load_trust_store(&data_dir()?)?)
}

fn save_trust(store: &TrustStore) -> Result<(), Box<dyn std::error::Error>> {
    save_trust_store(&data_dir()?, store)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("host") => host(args.next().unwrap_or_else(|| DEFAULT_PORT.to_string())).await?,
        Some("connect") => connect(&args.next().unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"))).await?,
        _ => {
            eprintln!("EstroDesk");
            eprintln!("  estrodesk host [port]");
            eprintln!("  estrodesk connect [address:port]");
            eprintln!("Set ESTRODESK_DATA_DIR to override the identity storage directory.");
        }
    }
    Ok(())
}

async fn host(port: String) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_identity()?;
    let trust = Arc::new(Mutex::new(load_trust()?));
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    println!("EstroDesk host listening on {port}");
    println!("Host identity fingerprint: {}", fingerprint(&identity.public_key_bytes()));
    println!("Warning: identity seed is a local file, not OS-keychain encrypted.");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        let host_identity = identity.clone();
        let host_trust = Arc::clone(&trust);
        println!("Incoming connection from {peer}");
        tokio::spawn(async move {
            if let Err(error) = host_connection(&mut stream, host_identity, host_trust).await {
                eprintln!("Connection error from {peer}: {error}");
            }
        });
    }
}

async fn host_connection(stream: &mut TcpStream, identity: DeviceIdentity, trust: Arc<Mutex<TrustStore>>) -> Result<(), Box<dyn std::error::Error>> {
    let hello = receive(stream).await?;
    let Message::Hello(hello) = hello.message else { return Err("expected Hello as first message".into()); };
    println!("Hello from {} ({})", hello.device_name, hello.device_id);
    let peer_name = hello.device_name.clone();
    let mut handshake = HostHandshake::new(identity);
    let ack = handshake.receive_hello(hello, "host", capabilities())?;
    send(stream, &Envelope::new(ack)).await?;

    let auth = receive(stream).await?;
    let Message::Authenticate(auth) = auth.message else { return Err("expected Authenticate after HelloAck".into()); };
    let controller_key: [u8; 32] = hex::decode(&auth.public_key)?.try_into().map_err(|_| "controller public key must be 32 bytes")?;

    let trust_status = { trust.lock().await.status(&controller_key) };
    match trust_status {
        Some(TrustStatus::Trusted) => println!("Trusted device recognized: {}", fingerprint(&controller_key)),
        Some(TrustStatus::Revoked) => {
            send_rejection(stream, "device is revoked").await?;
            return Err("connection rejected: device is revoked".into());
        }
        None if !approve(&peer_name, &controller_key) => {
            send_rejection(stream, "user rejected device pairing").await?;
            return Err("pairing rejected by user".into());
        }
        None => {}
    }

    let (ack, keys) = handshake.receive_authentication(auth)?;
    if trust_status.is_none() {
        let mut store = trust.lock().await;
        store.trust(controller_key, peer_name)?;
        save_trust(&store)?;
        println!("Device paired and saved to persistent trust store.");
    }
    send(stream, &Envelope::new(ack)).await?;

    let mut channel = SecureChannel::host(&keys.send_key, &keys.receive_key);
    let start = channel.receive(stream).await?;
    let Message::SessionStart(start) = start.message else { return Err("expected encrypted SessionStart".into()); };
    println!("Encrypted session established: {}", start.session_id);
    channel.send(stream, &Envelope::new(Message::SessionStarted(estrodesk_protocol::SessionStarted { session_id: start.session_id }))).await?;
    println!("Secure channel ready.");
    Ok(())
}

async fn send_rejection(stream: &mut TcpStream, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    send(stream, &Envelope::new(Message::AuthenticateAck(AuthenticationAck { accepted: false, reason: Some(reason.into()), public_key: None, proof: None }))).await?;
    Ok(())
}

async fn connect(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let identity = load_identity()?;
    let mut trust = load_trust()?;
    println!("Connecting to {address}");
    println!("Controller identity fingerprint: {}", fingerprint(&identity.public_key_bytes()));
    println!("Warning: identity seed is a local file, not OS-keychain encrypted.");

    let mut stream = TcpStream::connect(address).await?;
    let mut handshake = ControllerHandshake::new(identity);
    send(&mut stream, &Envelope::new(handshake.hello("controller", "EstroBunny", capabilities()))).await?;

    let response = receive(&mut stream).await?;
    let Message::HelloAck(ack) = response.message else { return Err("expected HelloAck".into()); };
    let host_key: [u8; 32] = hex::decode(&ack.public_key)?.try_into().map_err(|_| "host public key must be 32 bytes")?;

    match trust.status(&host_key) {
        Some(TrustStatus::Trusted) => println!("Trusted host recognized: {}", fingerprint(&host_key)),
        Some(TrustStatus::Revoked) => return Err("host is revoked in the local trust store".into()),
        None if !approve(&ack.device_id, &host_key) => return Err("user did not trust the host device".into()),
        None => {}
    }

    let auth = handshake.receive_hello_ack(ack)?;
    send(&mut stream, &Envelope::new(auth)).await?;
    let response = receive(&mut stream).await?;
    let Message::AuthenticateAck(ack) = response.message else { return Err("expected AuthenticationAck".into()); };
    let keys = handshake.receive_authentication_ack(ack)?;

    if trust.status(&host_key).is_none() {
        trust.trust(host_key, address)?;
        save_trust(&trust)?;
        println!("Host paired and saved to persistent trust store.");
    }

    let mut channel = SecureChannel::controller(&keys.send_key, &keys.receive_key);
    let id = session_id();
    channel.send(&mut stream, &Envelope::new(Message::SessionStart(estrodesk_protocol::SessionStart { session_id: id.clone() }))).await?;
    let response = channel.receive(&mut stream).await?;
    match response.message {
        Message::SessionStarted(start) if start.session_id == id => { println!("Encrypted session established: {id}"); println!("Secure channel ready."); }
        _ => return Err("unexpected encrypted session response".into()),
    }
    Ok(())
}
