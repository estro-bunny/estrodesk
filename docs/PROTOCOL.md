# EstroDesk Protocol v1

EstroDesk uses a versioned message envelope so peers can reject incompatible protocol versions before establishing a session.

## Initial flow

```text
Controller                         Host
    |                               |
    | -------- Hello -------------->|
    | <------- HelloAck ------------|
    | ----- Authenticate ---------->|
    | <---- AuthenticateAck --------|
    | ------ SessionStart ---------->|
    | <----- SessionStarted --------|
    |                               |
    | <====== active session ======> |
    |                               |
    | ------- SessionEnd ---------->|
    | <------ SessionEnded ---------|
```

## Design rules

- Every message is wrapped in an `Envelope` containing the protocol version.
- Version incompatibility must fail closed.
- Capabilities are negotiated explicitly rather than assumed.
- Authentication happens before a remote-control session starts.
- Session IDs identify individual control sessions.
- Ping/pong exists for transport liveness and latency measurement.
- Cryptographic implementation belongs in the crypto layer, not in protocol message definitions.

This document describes the wire contract only. It does not claim that authentication or encryption is secure until the corresponding implementation and tests exist.
