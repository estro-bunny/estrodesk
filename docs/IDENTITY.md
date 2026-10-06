# EstroDesk Device Identity

Every EstroDesk device has a persistent Ed25519 identity.

## Rules

- The Ed25519 public key is the device's cryptographic identity.
- The private signing seed never leaves the local device.
- Identity material is restored across launches rather than regenerated.
- Storage bytes are versioned and integrity-checked before restoration.
- The identity file must be protected by the operating system's local storage permissions.
- A future platform storage backend should use the OS credential/keychain facilities where available.

The crypto crate intentionally does not choose a filesystem path or silently write private
keys. That belongs to the platform application layer, where permissions and secure storage
facilities can be handled correctly for Windows and Linux.

## Pairing

A newly observed identity is not trusted merely because its signature verifies.

The application must present a visible first-pairing confirmation. After approval, the
peer public key is added to the local trust store. Revoked identities remain rejected
until the user explicitly re-pairs them.

## Security boundary

The current storage API serializes key material but does not encrypt it. Callers must
store the resulting bytes using an OS-protected mechanism. This is deliberately explicit:
we do not pretend that a plaintext key file is secure.
