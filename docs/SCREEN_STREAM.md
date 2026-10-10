# Screen streaming protocol

Status: protocol groundwork only. This document does not claim that frame encoding, binary payload transport, or platform capture is implemented.

## Control messages

- `ScreenStreamStart` requests a stream within an already authenticated session and declares stream ID, dimensions, codec, and target frame rate.
- `ScreenStreamStarted` confirms that the receiver accepted the stream.
- `ScreenFrame` describes one frame's metadata.
- `ScreenStreamStop` and `ScreenStreamStopped` stop a stream explicitly.

A stream message must be sent only inside the authenticated session it names. Receivers must reject unknown sessions/streams, unexpected codecs, non-monotonic frame IDs, and invalid state transitions when the stream state machine is implemented.

## Frame metadata and limits

- Maximum width or height: 16,384 pixels.
- Maximum total image area: 67,108,864 pixels.
- Maximum encoded payload: 16 MiB per frame.
- Target frame rate: 1–120 FPS.
- Session and stream IDs must be non-empty.
- Timestamp is monotonic microseconds from the sender's chosen stream clock; it is not wall-clock time.

These checks are defensive protocol limits, not a guarantee that a given machine can decode a frame within its resource budget.

## Payload framing

Frame pixels are deliberately not embedded in the JSON metadata. Serializing raw pixels as JSON arrays would be wasteful and easy to misuse. The future transport layer must bind each binary payload to its validated header, enforce the declared length before allocation, authenticate it with the secure channel, and drop stale frames rather than queueing unbounded latency.

The protocol currently names RawBgra8, JPEG, H.264, and VP9 as codec identifiers. Naming a codec does not mean an encoder/decoder or negotiation policy is implemented. Codec support must be advertised and selected explicitly before streaming.

## Next implementation steps

1. Add bounded binary payload framing to the secure transport.
2. Add stream state tracking and frame-ID monotonicity checks.
3. Introduce an encoder trait and a deterministic fake encoder for tests.
4. Add platform capture backends (Windows Graphics Capture/DXGI; Linux portal/PipeWire for Wayland).
5. Test Windows and Linux firewall, capture permissions, and teardown behavior.
