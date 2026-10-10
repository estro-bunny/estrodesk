# EstroDesk LAN Discovery

## Current mechanism

The desktop host listens for IPv4 UDP discovery requests on port 45822. A controller sends one broadcast request and listens for matching replies for up to three seconds. A response advertises:

- protocol version
- a request identifier echoed from the query
- device label
- public-key hex and a matching public-key-derived device identifier
- TCP port
- currently advertised capabilities

The controller uses the response's source IP plus advertised TCP port as the candidate address. Discovery results are deduplicated by identity hint and address.

## Trust boundary

Discovery is an unauthenticated convenience mechanism, not an identity protocol. Any machine on the LAN may send fake responses, copy a label, advertise a different address, or replay public metadata. The request identifier filters unrelated replies but is not a secret and does not authenticate a responder.

Never authorize a session based on discovery data. The normal TCP handshake must still verify the peer's cryptographic proof and apply the existing explicit first-pair fingerprint approval / persisted trust policy. The fingerprint shown during that approval comes from the key presented in the authenticated handshake, not from the discovery packet.

Only public metadata is broadcast. Private identity material is never included. Discovery does not enable remote control by itself.

## Ports and operation

- UDP 45822: discovery request/reply
- TCP 45821 by default: authenticated session bootstrap and encrypted channel
- A custom host TCP port is advertised in the UDP response.

Run `estrodesk host [port]` on the host. Run `estrodesk discover` to list candidates, or `estrodesk connect` to select a candidate and continue through the existing pairing flow. A manual `estrodesk connect address:port` remains available.

Broadcast discovery may not cross VLANs, guest Wi-Fi isolation, VPN interfaces, or routed subnets. Firewalls must allow the relevant local-network UDP and TCP traffic. The current MVP uses IPv4 limited broadcast and does not provide mDNS, IPv6, or cross-subnet discovery.

## Hardening still needed

- Add unit/integration tests for malformed, oversized, mismatched, and duplicate discovery packets.
- Add explicit rate limiting for replies and defensive per-source limits.
- Test broadcast behavior and firewall guidance on Windows and Linux.
- Add configurable interface selection and IPv6/mDNS only if there is a demonstrated need.
- Review the complete application and handshake before any production-security claim.
