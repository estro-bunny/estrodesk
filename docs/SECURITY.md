# EstroDesk Security

EstroDesk is an early prototype. Its current handshake and encrypted transport are not a substitute for a production security audit.

## Identity and local storage

- Each installation generates or loads a persistent Ed25519 signing identity.
- The public key identifies the device; private key material must never be sent to a peer.
- The signing seed is currently stored in a local file with restrictive filesystem permissions where supported. It is **not** encrypted by Windows DPAPI, Credential Manager, Linux Secret Service, or another OS key store. Treat local-account compromise as a possible identity compromise.
- Trust metadata records trusted and revoked public keys. It is not secret, but malformed or unsupported data must fail closed.

## Authentication and encryption

- The session handshake uses Ed25519 signatures to prove possession of identity keys and X25519 ephemeral key exchange to derive a shared secret.
- HKDF-SHA256 derives separate controller-to-host and host-to-controller keys.
- ChaCha20-Poly1305 protects secure-channel payloads; sequence numbers and direction markers are authenticated as associated data.
- These are prototype-level implementation choices. Do not describe the whole application as production-secure until the handshake, key lifecycle, transport, and platform integrations receive independent review.

## LAN discovery

LAN discovery is unauthenticated UDP metadata used only to find candidate hosts. Names, addresses, capabilities, and advertised public keys can be spoofed. Discovery never authorizes a session; the TCP handshake and explicit fingerprint approval remain mandatory for first pairing.

## Rules

- Use established cryptographic primitives; do not invent cryptography.
- Never transmit private keys.
- Fail closed on authentication errors, revoked peers, malformed data, and protocol-version mismatch.
- Keep first-time pairing and trust state visible to the user.
- Do not add stealth persistence, hidden access, or remote-control activation without explicit consent.
- Security claims require tests, platform validation, and review before release.

## Known work remaining

- OS-protected identity storage (Windows and Linux).
- Atomic writes and corruption recovery for the persistent trust store.
- Handshake/session timeout and denial-of-service limits.
- Discovery rate limiting and cross-platform LAN/firewall testing.
- End-to-end integration tests, dependency review, and independent security audit.
