# EstroDesk Transport

The initial transport uses a small length-delimited framing layer over an async byte stream.

```text
+----------------+----------------------+
| 4-byte length  | JSON Envelope bytes  |
| big-endian     |                      |
+----------------+----------------------+
```

## Safety properties

- Maximum frame size: 1 MiB.
- Length is validated before allocation.
- Protocol version validation occurs after decoding.
- Unexpected EOF is treated as connection closure.
- The framing layer does not provide encryption.

The current implementation is transport-agnostic and can sit on TCP or another reliable byte stream. TLS/noise-style authenticated encrypted transport will be added before remote-control traffic is considered production-ready.
