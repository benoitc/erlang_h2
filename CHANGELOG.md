# Changelog

All notable changes to `h2` are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-04-19

### Added
- `h2_settings`: WebTransport over HTTP/2 settings (draft-ietf-webtrans-http2-14 §11.2). IDs `0x2b61`-`0x2b66` encode/decode as `wt_initial_max_data`, `wt_initial_max_stream_data_uni`, `wt_initial_max_stream_data_bidi_local`, `wt_initial_max_stream_data_bidi_remote`, `wt_initial_max_streams_uni`, `wt_initial_max_streams_bidi`. No defaults: absence means "not advertised".

### Changed
- `h2_settings:decode/1`: unknown setting IDs are preserved under their raw 16-bit integer key in the returned map instead of being dropped. RFC 7540 §6.5.2 "MUST ignore" means "do not act on", not "discard"; keeping them lets higher layers (e.g. WebTransport) inspect extension settings without a patch here. `h2_settings:encode/1` also accepts integer keys for symmetric round-trip.

## [0.4.0] - 2026-04-15

Listener robustness + TLS regression guard. The server listener no longer dies when the process that called `h2:start_server/2` exits, which broke test helpers and init callbacks spinning up short-lived listeners.

### Added
- `h2_app` / `h2_sup` / `h2_listener`: `h2` is now a proper OTP application with a top-level `simple_one_for_one` supervisor for per-server listeners. Server listeners live under the application supervision tree instead of being linked to the caller of `h2:start_server/2`.
- CT regression `tls_transport_tag_detected_test` in `h2_compliance_SUITE`: asserts `h2_connection` classifies the TLS socket as `ssl` (not `gen_tcp`) after connect, so any future drift in OTP's `sslsocket` tuple shape is caught early.

### Changed
- **Breaking:** `h2:start_server/2` now requires the `h2` application to be started (`application:ensure_started(h2)`). Previously it worked from any process; now it registers a child under `h2_sup`.
- `h2:stop_server/1` sends a stop message to the listener process and lets it shut down the acceptor pool and close the listen socket under OTP supervision.

### Fixed
- `wait_connected/1,2` callers and the `{h2, Conn, connected}` owner event are now fired inline from `handle_frame` when the first SETTINGS ack transitions the connection to `connected`. Previously, if the same socket read buffer also contained a frame that caused a connection error, `gen_statem` would enter `closing` before the `connected` state-enter callback ran and waiters would only see the teardown reply.
- `closing` state-enter now replies to any still-queued `wait_connected/1,2` callers with `{error, ErrorCode}` instead of leaving them to time out.
- `closing` state-enter now half-closes the write side (`shutdown(write)`) and keeps reading to drain the recv buffer before the final close. A full `close()` with unread peer data was causing Linux to emit RST instead of FIN, which masked our GOAWAY on the h2spec oversized-frame case (`4.2 / 2: Sends a large size DATA frame that exceeds SETTINGS_MAX_FRAME_SIZE`).

## [0.3.0] - 2026-04-15

Third review pass + h2spec interop; behaviour-visible spec fixes across the whole state machine. No breaking API change, but callers that matched on specific error atoms may see different values on edge cases (ALPN, ENABLE_PUSH, IWS).

### Added
- External interop suite `test/h2_interop_SUITE.erl` drives the server from [h2spec](https://github.com/summerwind/h2spec). Six groups: TLS generic/HPACK, h2c plaintext generic/HPACK, small-window (forced flow-control fragmentation), `--strict` mode. 146/146 generic+HPACK cases pass. Skips cleanly when `h2spec` is not on `$PATH`.
- `.github/workflows/interop.yml`: CI runs h2spec v2.6.0 on every push/PR; logs uploaded on failure.
- `.github/workflows/ci.yml`: now runs `h2_compliance_SUITE` in addition to eunit; CT logs uploaded on failure.
- PING/RST_STREAM flood mitigation (RFC 9113 §10.5): per-second counters per connection, GOAWAY(ENHANCE_YOUR_CALM) on overflow.
- Extended CONNECT (RFC 8441): server opt-in via `h2:start_server(Port, #{enable_connect_protocol => true, ...})` advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`. Client uses `h2:request(Conn, Headers, #{protocol => <<"websocket">>})`. New errors: `{error, extended_connect_disabled}`, `{error, extended_connect_method}`. Inbound: server rejects `:protocol` with stream `PROTOCOL_ERROR` if it has not opted in.
- `h2:start_server` honors `transport => tcp` (cleartext h2c prior-knowledge listener with gen_tcp acceptor pool).
- `h2:connect/3` top-level `verify` and `cacerts` options merged into SSL options.
- Owner event `{h2, Conn, {informational, StreamId, Status, Headers}}` for 1xx interim responses (excluding 101).
- Send-side header validation runs before HPACK encode on `send_request`, `send_request_headers`, `send_response`, and `send_trailers`.
- README: "Using with Ranch" and "Coexisting with HTTP/1.1" sections with code sketches.

### Changed
- `SETTINGS_ENABLE_PUSH` default is now **0** (was 1). Server advertises 0; inbound PUSH_PROMISE on either side is a connection PROTOCOL_ERROR (RFC 9113 §6.5.2 / §8.4).
- TLS `connect/2,3` requires ALPN `h2`. Previously fell through silently on `protocol_not_negotiated`; now returns `{error, alpn_not_negotiated}` (§3.3).
- Connection-level receive window fixed at 65535 regardless of `SETTINGS_INITIAL_WINDOW_SIZE` (§6.9.2). IWS now only adjusts stream windows.
- Request builder no longer injects `:authority = ""` when the caller omits `host`. Non-CONNECT requests without host now send no `:authority`; CONNECT without host returns `{error, missing_authority}` (§8.3.1).
- Trailers from the peer transition the stream to `half_closed_remote` (was `closed`), so a handler mid-response isn't surprised by `invalid_stream_state` when the peer pipelines body+trailers (§5.1).
- `closing` state proactively closes the TCP/TLS socket on entry (§5.4) instead of waiting up to 5 s for the peer.
- Closed-stream error classification: closed-reason retained in a compact id → reason side map bounded at 10 000 entries. Late DATA/HEADERS on a recently-closed stream is scoped exactly (connection vs stream) regardless of whether the full record has been evicted from the 100-entry window.
- Owner event `{h2, Conn, {goaway, LastStreamId}}` is now `{goaway, LastStreamId, ErrorCode}`.
- Per-stream events (`data`, `trailers`, `stream_reset`) routed to the registered stream handler when set; connection owner receives them only as fallback.
- HEADERS whose encoded block exceeds peer `SETTINGS_MAX_FRAME_SIZE` are split into HEADERS + CONTINUATION chain (§4.2).
- Body-less responses (HEAD / 204 / 304) emit a trailing `{data, Sid, <<>>, true}` event so callers waiting for end-of-stream don't hang.
- HPACK: Huffman encode/decode tables precomputed once via `persistent_term` + `-on_load`; dynamic table caches length and uses a single `lists:reverse` on eviction.

### Fixed
- HEADERS/DATA on a stream closed via END_STREAM: connection STREAM_CLOSED (was stream-scoped RST) (§5.1).
- HEADERS/DATA on a stream closed via RST_STREAM: stream-scoped STREAM_CLOSED (was connection-scoped).
- CONTINUATION without an outstanding pending HEADERS: connection PROTOCOL_ERROR (§6.10).
- PRIORITY self-dependency on both the PRIORITY frame and inline HEADERS priority: stream PROTOCOL_ERROR (§5.3.1).
- PRIORITY frame with length != 5: stream FRAME_SIZE_ERROR (was connection) (§6.3).
- WINDOW_UPDATE on an idle stream: connection PROTOCOL_ERROR (was silently ignored) (§5.1).
- Unknown frame types: ignored per §4.1 (previously function_clause-crashed the connection).
- Inbound `MAX_CONCURRENT_STREAMS` enforced: peer HEADERS over our advertised limit now get `RST_STREAM(REFUSED_STREAM)` (§5.1.2).
- `SETTINGS_ENABLE_PUSH=1` received as client: connection PROTOCOL_ERROR (§6.5.2).
- `SETTINGS_INITIAL_WINDOW_SIZE` above 2³¹−1: connection FLOW_CONTROL_ERROR (was PROTOCOL_ERROR) (§6.9.2).
- Body-less responses (HEAD/204/304): accept `content-length > 0` with `END_STREAM` (RFC 9110 §9.3.2); reject when `END_STREAM` is absent on the header block.
- `in_closed_stream_range` was asymmetric in client mode (only matched peer-initiated ids); now mirrors server mode.
- HPACK decoder: truncated literal returns `{error, incomplete_string}` instead of `function_clause`.
- 1xx interim responses with `END_STREAM` or `Content-Length` → stream `PROTOCOL_ERROR` (§8.1, RFC 9110 §15.2).
- CONNECT tunnel flag no longer pre-set on the request; the stream becomes a tunnel only when the 2xx response is sent/received. Non-2xx CONNECT responses permit trailers and enforce body rules (RFC 7540 §8.3).
- `:authority` containing userinfo (`user@host`) rejected with `PROTOCOL_ERROR` on both inbound and outbound paths (§8.3.1); `check_authority_host` runs for CONNECT requests too.
- Extended CONNECT `:protocol` value validated as an RFC 7230 token (RFC 8441 §4).
- `:scheme` pseudo-header follows the actual transport (`http` on TCP, `https` on TLS).
- `:method = CONNECT` outbound: trailers rejected with `{error, tunnel_no_trailers}`.
- `WINDOW_UPDATE` with increment 0 on a non-zero stream → stream RST_STREAM(`PROTOCOL_ERROR`) (§6.9.1).
- `:status` parsing: malformed values trigger stream `PROTOCOL_ERROR` instead of crashing the gen_statem.
- `:status = 101` rejected on both send and receive (§8.6).
- Padding counted against receive flow control (§6.1). Connection-level receive window consumed on DATA for closed or unknown streams (§5.1).
- `Content-Length` enforcement (§8.1.1): duplicate/mismatched/non-numeric/negative values → `PROTOCOL_ERROR`; DATA overshoot or END_STREAM mismatch → stream RST.
- Server-side request trailers: trailing HEADERS without END_STREAM → `PROTOCOL_ERROR`.
- Field name validation tightened to RFC 7230 `tchar` (rejects SP, HTAB, colon in regular headers, other controls, DEL, non-ASCII). Field values: leading/trailing SP/HTAB rejected in addition to NUL/CR/LF.
- `SETTINGS_MAX_HEADER_LIST_SIZE` enforced in both directions: outbound exceed → `{error, header_list_too_large}`; inbound exceed → stream `PROTOCOL_ERROR`.

### Docs
- `docs/features.md`: PRIORITY metadata is parsed and self-dep rejected, but no scheduler is implemented (RFC 9218 supersedes RFC 7540 priorities).

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
