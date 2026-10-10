# EstroDesk Transport

EstroDesk uses length-delimited frames over a reliable byte stream such as TCP.

## Bootstrap framing

Before authentication, the desktop bootstrap exchanges protocol `Envelope` values using:

```text
+----------------+----------------------+
| 4-byte length  | JSON Envelope bytes  |
| big-endian     |                      |
+----------------+----------------------+
```

Frames larger than 1 MiB are rejected and protocol versions are validated before dispatch.

## Secure channel

After the authenticated handshake completes, plaintext framing is replaced by `SecureChannel`:

```text
+----------------+----------------+----------------------------+
| 4-byte length  | 8-byte sequence| ChaCha20-Poly1305 payload |
| big-endian     |                | + authentication tag      |
+----------------+----------------+----------------------------+
```

The secure channel derives independent controller→host and host→controller keys from the X25519 shared secret and signed handshake transcript. Sequence numbers are authenticated as associated data and must increase exactly by one. Replay, reordering, and authentication failures are rejected.

The nonce is derived from a fixed direction marker plus the monotonically increasing sequence number. It is not supplied by the remote peer independently of the authenticated frame sequence.

## Desktop integration

The desktop binary now performs:

```text
TCP connect/accept
      ↓
Hello / HelloAck
      ↓
user-visible trust prompt
      ↓
Authenticate / AuthenticationAck
      ↓
X25519 + HKDF directional keys
      ↓
SecureChannel
      ↓
encrypted SessionStart / SessionStarted
```

This is an authenticated encrypted-session prototype, not a production remote-desktop implementation. Device identities and trust decisions persist locally, but the identity signing seed is currently stored as a plaintext file protected only by filesystem permissions; it is not encrypted by the OS keychain. LAN discovery uses unauthenticated UDP metadata and must never be treated as proof of identity. OS-protected identity storage, atomic trust-store writes, timeouts, network hardening, platform testing, and independent security review remain required before treating the pairing system as production-ready.
