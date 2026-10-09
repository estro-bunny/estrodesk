# EstroDesk Device Identity

Every EstroDesk device has a persistent Ed25519 identity.

## Rules

- The Ed25519 public key is the device's cryptographic identity.
- The private signing seed never leaves the local device.
- Identity material is restored across launches rather than regenerated.
- Storage bytes are versioned and validated before restoration.
- First pairing always requires a visible user confirmation.
- Revoked identities must remain rejected until the user explicitly re-pairs them.

## Current desktop storage

The desktop currently stores the serialized identity in `identity.bin` under its configured data directory:

- Set `ESTRODESK_DATA_DIR` to override the directory.
- On Windows, the default uses `%APPDATA%\EstroDesk`.
- On Linux, the default uses `$XDG_DATA_HOME/estrodesk`; configure `XDG_DATA_HOME` if your environment does not provide it.
- On Unix, the identity file is created with mode `0600`.

**Security limitation:** the seed is currently stored as plaintext bytes in a local file. Unix file permissions reduce access by other local users, but do not protect against malware running as the same user, administrator/root access, disk theft, or backups containing the file. Windows currently relies on the user's application-data directory ACLs. This is persistence, not OS-keychain encryption.

A future platform storage backend should use Windows Credential Manager/DPAPI and an appropriate Linux secret service or another platform-specific protected store. Do not describe the current implementation as encrypted or production-secure.

## Pairing

A newly observed identity is not trusted merely because its signature verifies. The application presents a visible first-pairing confirmation. Persistent trust must be stored separately from identity material and support explicit revoke/forget operations.

## Key handling

Never transmit private identity material. Do not silently replace a malformed identity file with a new key: fail closed and require the user to resolve the problem, so an existing device identity cannot be silently lost or changed.
