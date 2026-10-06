use estrodesk_protocol::{Capabilities, Envelope, Message};
use estrodesk_transport::{receive, send};
use std::env;
use tokio::net::{TcpListener, TcpStream};

const DEFAULT_PORT: u16 = 45821;

fn capabilities() -> Capabilities {
    Capabilities {
        screen: true,
        input: true,
        clipboard: true,
        files: false,
        audio: false,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("host") => host(args.next().unwrap_or_else(|| DEFAULT_PORT.to_string())).await?,
        Some("connect") => {
            let address = args.next().unwrap_or_else(|| format!("127.0.0.1:{DEFAULT_PORT}"));
            connect(&address).await?;
        }
        _ => {
            eprintln!("EstroDesk");
            eprintln!("  estrodesk host [port]");
            eprintln!("  estrodesk connect [address:port]");
        }
    }

    Ok(())
}

async fn host(port: String) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    println!("EstroDesk host listening on {port}");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        println!("Incoming connection from {peer}");

        tokio::spawn(async move {
            let result = async {
                let envelope = receive(&mut stream).await?;
                match envelope.message {
                    Message::Hello(hello) => {
                        println!("Hello from {} ({})", hello.device_name, hello.device_id);
                        send(
                            &mut stream,
                            &Envelope::new(Message::HelloAck(
                                estrodesk_protocol::HelloAck {
                                    device_id: "host".into(),
                                    capabilities: capabilities(),
                                    public_key: String::new(),
                                    ephemeral_public_key: String::new(),
                                },
                            )),
                        )
                        .await?;
                    }
                    _ => eprintln!("Rejected unexpected first message"),
                }
                Ok::<(), estrodesk_transport::TransportError>(())
            }.await;

            if let Err(error) = result {
                eprintln!("Connection error: {error}");
            }
        });
    }
}

async fn connect(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    println!("Connected to {address}");

    let hello = Envelope::new(Message::Hello(estrodesk_protocol::Hello {
        device_id: "controller".into(),
        device_name: "EstroBunny".into(),
        capabilities: capabilities(),
    }));

    send(&mut stream, &hello).await?;
    let response = receive(&mut stream).await?;

    match response.message {
        Message::HelloAck(ack) => {
            println!("Host accepted hello: {}", ack.device_id);
        }
        _ => println!("Unexpected response"),
    }

    Ok(())
}
