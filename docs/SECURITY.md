# EstroDesk Security

## Identity

Every device will have a persistent Ed25519 signing identity. The public key identifies the device; the private key must never leave that device.

## Authentication

The protocol will use signed handshake material to prove possession of a device identity. Trust decisions belong to the user and pairing layer.

## Encryption

Identity signatures are **not** encryption. Transport confidentiality and forward secrecy will be implemented separately using an established, audited protocol/library.

## Rules

- Never invent cryptographic primitives.
- Never transmit private keys.
- Fail closed on authentication errors.
- Make remote-control consent explicit.
- Keep pairing and trust state visible to the user.
- Do not add stealth persistence or hidden access.
- Security claims require tests and review before release.
