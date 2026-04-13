# Changelog

All notable changes to `h2` are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-04-13

First usable release with a full connection-layer client and server. Previous 0.1.0 shipped only frame/HPACK primitives.

### Added
- Public API module `h2` with client and server entry points aligned with `quic_h3`:
  - `h2:connect/2,3`, `h2:wait_connected/1,2`
  - `h2:request/2,3,4,5`, `h2:send_data/3,4`, `h2:send_trailers/3`
  - `h2:start_server/2,3`, `h2:stop_server/1`, `h2:server_port/1`
  - `h2:send_response/4`, `h2:cancel/2,3`, `h2:cancel_stream/2,3`
  - `h2:set_stream_handler/3,4`, `h2:unset_stream_handler/2`
  - `h2:goaway/1,2`, `h2:close/1`, `h2:controlling_process/2`
  - `h2:get_settings/1`, `h2:get_peer_settings/1`
- `h2_connection` gen_statem implementing the full stream state machine (RFC 7540 §5.1) with flow control, SETTINGS negotiation, two-phase GOAWAY, and CONTINUATION handling.
- CONNECT tunnel mode (RFC 7540 §8.3): bidirectional byte tunnels over a stream, half-close semantics, trailers rejection, `Content-Length`/`Transfer-Encoding` rejection on 2xx.
- `h2_server` with TLS acceptor pool and ALPN `h2` negotiation.
- Owner-process event messages: `{h2, Conn, {response, ...}}`, `{data, ...}`, `{trailers, ...}`, `{stream_reset, ...}`, `{goaway, ...}`, `closed`, `connected`.
- Compliance test suite (Common Test) with 32 cases covering protocol conformance, API parity, and tunnel mode.

### Changed
- `h2_hpack`: persistent_term-backed precomputed Huffman encode tuple and sorted decode table; static table lookups via `element/2` (O(1)); dynamic table caches length and evicts with a single `lists:reverse`.
- `h2_connection`: cached `peer_max_frame_size`, `peer_initial_window_size`, `peer_max_concurrent_streams` on the state record; CONTINUATION header buffer uses `iodata()` (flattened once on END_HEADERS) instead of per-frame binary concatenation.
- Frame decoder (`h2_frame:decode/2`) takes `MaxFrameSize` and enforces per-type stream-id 0 rules (DATA/HEADERS/PRIORITY/RST_STREAM/PUSH_PROMISE/CONTINUATION reject 0; SETTINGS/PING/GOAWAY require 0).

### Fixed
- RFC 7540/7541 compliance gaps:
  - Padding bound in DATA/HEADERS frames now accepts `PadLength == byte_size(Rest)`.
  - `WINDOW_UPDATE` increment 0: stream-level RST_STREAM / connection-level GOAWAY with `PROTOCOL_ERROR`.
  - `SETTINGS_INITIAL_WINDOW_SIZE` change that overflows any open stream → connection `FLOW_CONTROL_ERROR`.
  - Pseudo-header validation: order, lowercase header names, connection-specific headers rejected, `:path`/`:authority` checks.
  - CONTINUATION interleaving on a different stream → `PROTOCOL_ERROR`.
  - RST_STREAM on an idle stream → `PROTOCOL_ERROR`.
  - HEADERS on a half-closed-remote or closed stream → `STREAM_CLOSED`.
  - HPACK: dynamic-table size update larger than peer-advertised max → `COMPRESSION_ERROR`; size update after a non-size-update representation → `COMPRESSION_ERROR`.
  - Huffman decoder: EOS symbol in the middle of a string rejected; padding must be < 8 bits of all-ones.
- Body duplication when `send_data` split buffers across frames.
- Connection owner notified with `closed` on termination.
- CT suite flakiness: acceptor socket defaulted to active mode, losing data between `ssl:handshake` return and `setopts({active, false})`.

## [0.1.0]

Initial release. Low-level HTTP/2 primitives (frames, HPACK, settings, capsule, varint).
