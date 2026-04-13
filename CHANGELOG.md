# Changelog

All notable changes to `h2` are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Extended CONNECT (RFC 8441): server opt-in via `h2:start_server(Port, #{enable_connect_protocol => true, ...})` advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`. Client uses `h2:request(Conn, Headers, #{protocol => <<"websocket">>})`. New errors: `{error, extended_connect_disabled}` (peer never advertised the setting), `{error, extended_connect_method}` (`:protocol` requires `:method=CONNECT`). Inbound: server rejects `:protocol` with stream `PROTOCOL_ERROR` if it has not opted in.
- `h2:start_server` now honors `transport => tcp` (cleartext h2c prior-knowledge listener with gen_tcp acceptor pool).
- `h2:connect/3` top-level `verify` and `cacerts` options are merged into SSL options (typespec no longer lies).
- Owner event `{h2, Conn, {informational, StreamId, Status, Headers}}` for 1xx interim responses (excluding 101).
- Send-side header validation runs before HPACK encode on `send_request`, `send_request_headers`, `send_response`, and `send_trailers`.
- CT `compliance_v2` group: 22 new cases covering second-look audit findings and Extended CONNECT.

### Changed
- Owner event `{h2, Conn, {goaway, LastStreamId}}` is now `{goaway, LastStreamId, ErrorCode}` (was always documented as 3-tuple).
- Per-stream events (`data`, `trailers`, `stream_reset`) routed to the registered stream handler when set; connection owner receives them only as fallback.
- HEADERS frames whose encoded block exceeds peer `SETTINGS_MAX_FRAME_SIZE` are automatically split into HEADERS + CONTINUATION chain (RFC 9113 §4.2).
- Body-less responses (HEAD / 204 / 304) emit a trailing `{data, Sid, <<>>, true}` event so callers waiting for end-of-stream don't hang (matches quic_h3).
- HPACK: Huffman encode/decode tables precomputed once via `persistent_term` + `-on_load`; dynamic table caches length and uses a single `lists:reverse` on eviction.
- CONTINUATION accumulator uses `iodata()` instead of per-frame binary concatenation.
- Cached `peer_max_frame_size` / `peer_initial_window_size` / `peer_max_concurrent_streams` on the connection state record.

### Fixed
- `SETTINGS_ENABLE_PUSH` is now always advertised as 0 (RFC 9113 §6.5.2). Was incorrectly sending 1 while rejecting PUSH_PROMISE.
- `:scheme` pseudo-header now follows the actual transport (`http` on TCP, `https` on TLS). Previously hardcoded to `https`.
- `:method = CONNECT` outbound: trailers rejected with `{error, tunnel_no_trailers}`.
- `WINDOW_UPDATE` with increment 0 on a non-zero stream is now a stream-level RST_STREAM with `PROTOCOL_ERROR` (§6.9.1). Was a connection GOAWAY.
- `:status` parsing: malformed values trigger stream `PROTOCOL_ERROR` instead of crashing the gen_statem via `binary_to_integer`.
- `:status = 101` rejected on both send and receive (§8.6).
- Padding counted against receive flow control (§6.1). Decoder returns the full padded payload size; windows charged correctly.
- Connection-level receive window consumed on DATA for closed or unknown streams (§5.1). Previously the peer could overshoot our advertised window via post-reset DATA.
- `Content-Length` enforcement (§8.1.1): duplicate/mismatched/non-numeric/negative values → `PROTOCOL_ERROR`; DATA overshoot or END_STREAM mismatch → stream RST.
- Body forbidden on HEAD requests (client-side), 204, and 304 — enforced via `body_forbidden` stream flag.
- Server-side request trailers: trailing HEADERS without END_STREAM → `PROTOCOL_ERROR`.
- Field name validation tightened to RFC 7230 `tchar` (rejects SP, HTAB, colon in regular headers, other controls, DEL, non-ASCII). Field values: leading/trailing SP/HTAB rejected in addition to NUL/CR/LF.
- `SETTINGS_MAX_HEADER_LIST_SIZE` now enforced in both directions: outbound exceed → `{error, header_list_too_large}`; inbound exceed → stream `PROTOCOL_ERROR`.

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
