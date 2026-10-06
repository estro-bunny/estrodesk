# EstroDesk Handshake

The EstroDesk handshake authenticates both endpoints before a secure remote-control
session is established.

## Flow

```text
Controller                                      Host
    |                                             |
    | -------- Hello ---------------------------> |
    |                                             |
    | <------- HelloAck + host identity --------- |
    |                                             |
    | ---- Authenticate + signed transcript ----> |
    |                                             |
    | <--- AuthenticationAck + signed transcript - |
    |                                             |
    | ===== derive directional session keys ===== |
    |                                             |
    | ========= encrypted channel ============== |
```

## Cryptographic binding

The signed handshake transcript is:

```text
ESTRODESK-HANDSHAKE-V1
controller Ed25519 public key
host Ed25519 public key
controller X25519 ephemeral public key
host X25519 ephemeral public key
```

Both sides sign the same transcript. This binds the long-term identities to the
ephemeral key exchange and prevents an endpoint from silently swapping key
material during authentication.

The resulting X25519 shared secret is expanded with HKDF-SHA256 into two
direction-specific 32-byte keys:

- controller -> host
- host -> controller

The transport layer then uses those keys with ChaCha20-Poly1305 and a
monotonically increasing sequence number.

## Trust model

Authentication proves possession of a device identity key. It does **not** yet
define whether that identity is trusted by the local user.

Persistent device pairing, first-seen confirmation, revocation, and UI-visible
trust decisions are intentionally a separate layer.

## Current security boundary

This implementation is a protocol foundation, not a security audit.

Before internet-facing deployment we still need:

- persistent identity storage protected by the host OS
- explicit first-pairing and trust UX
- identity revocation
- session timeout and teardown rules
- handshake timeout/state-machine hardening
- interoperability tests over real sockets
- fuzzing and malformed-message testing
- independent security review
