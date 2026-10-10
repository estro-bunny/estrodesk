# EstroDesk 🐰💻

**Remote control. Maximum chaos.**

EstroDesk is an open-source remote desktop platform built as part of the EstroBunny universe.

The goal is simple: fast, secure, cross-platform remote access without the usual boring UX.

## Status

🚧 **Very early development** — architecture and protocol work are starting now.

## Architecture

EstroDesk is being built as a Rust workspace with clear boundaries between the protocol, security, transport, platform capabilities, desktop application, and relay infrastructure.

```text
estrodesk/
├── apps/
│   ├── desktop/
│   └── relay/
├── crates/
│   ├── protocol/
│   ├── crypto/
│   ├── transport/
│   ├── screen/
│   ├── input/
│   └── files/
├── docs/
└── Cargo.toml
```

## Development principles

- Security is designed in from the beginning.
- LAN-first for the initial MVP.
- The protocol stays independent from the UI.
- Cross-platform support is a first-class concern.
- No telemetry by default.
- Features should earn their complexity.

## LAN discovery

Run `estrodesk host [port]` on the machine you want to share, then run `estrodesk connect` on the controller. The controller broadcasts a short discovery request over IPv4 UDP port 45822, lists responding hosts, and lets you choose one. The host accepts the actual authenticated session over TCP (default port 45821).

Discovery packets contain only public metadata and are not authenticated. Names, addresses, capabilities, and advertised public keys can be spoofed; discovery never grants trust or bypasses the existing cryptographic handshake and visible fingerprint approval. Firewalls may need to allow UDP 45822 and the selected TCP host port on the local network.

For troubleshooting, `estrodesk discover` lists hosts without connecting, and `estrodesk connect address:port` still supports a manual address.

## Initial MVP

1. Establish authenticated peer identity.
2. Connect two machines on a local network.
3. Negotiate a session.
4. Stream the host screen.
5. Send mouse and keyboard input.

Everything else comes after that foundation works reliably.

## License

AGPL-3.0-or-later
