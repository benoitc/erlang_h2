# The wire codecs

This page describes the modules that turn bytes into terms and back. Read it
when you change a frame layout, header compression, a setting, or a capsule.
For how a connection uses them, see [Architecture](../architecture.md).

These modules hold no connection process and no socket. They are pure
functions, which is why they are tested with exact byte vectors and
properties (`test/h2_prop_tests.erl`) rather than with sockets.

| Module | What it does | What it checks | What it leaves to `h2_connection` |
| --- | --- | --- | --- |
| `h2_frame` | Encodes and decodes the ten frame types (RFC 9113 §6). Constructors such as `headers/3` and `data/3` build the terms `encode/1` takes. | Frame size against the maximum, stream id 0 where required or forbidden, padding, fixed payload lengths. A violation scoped to one stream is returned as `{error, {stream_error, StreamId, Code}, Rest}`. | Whether the frame is allowed in the current stream state. |
| `h2_hpack` | Header compression (RFC 7541): static and dynamic tables, integer and string coding, Huffman. A context is a value you thread through `encode/2` and `decode/2`. | Table size updates, index bounds, malformed integers and Huffman padding. | Header semantics: pseudo-headers, forbidden fields, list size. |
| `h2_settings` | The settings map: defaults, encode, decode, merge, validate. Extension settings are kept under their raw 16-bit id. | Value ranges for the known parameters. | When a setting takes effect and what it changes on open streams. |
| `h2_error` | Maps error codes between numbers, atoms and text. | | |
| `h2_varint` | Variable-length integers (RFC 9000 §16), used by capsules. | Range, up to 2^62 - 1. | |
| `h2_capsule` | The Capsule Protocol (RFC 9297): type, length, payload, carried in the DATA of an Extended CONNECT tunnel. | Truncated capsules are reported as incomplete so you can wait for more bytes. | Everything about what a capsule means. That belongs to the protocol in the tunnel. |

## Notes

- `h2_capsule`, `h2_varint` and `h2_error` are called directly by other
  projects. Changing an exported function there is an API change.
- The HPACK decoding context must see every header block of a connection in
  order. A decode error is always a connection error.
- The Huffman table is generated data in `include/h2_hpack_huffman.hrl`. Do
  not edit it by hand.
- Frame type numbers, setting ids, error codes and default limits are in
  `include/h2.hrl`.
