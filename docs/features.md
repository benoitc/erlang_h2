# Features

`h2` implements HTTP/2 as a client and a server on top of Erlang/OTP sockets. This page lists what is supported, what is intentionally left out, and the internal modules a library user may want to know about.

## Supported

### Protocol (RFC 7540)

- Connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) and exact-match validation on the server.
- All frame types: `DATA`, `HEADERS`, `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, `CONTINUATION`. `PUSH_PROMISE` is decoded but not generated (push disabled).
- Stream state machine per §5.1 with correct transitions for `idle → open → half_closed_{local,remote} → closed`, including reserved states for reception of PUSH_PROMISE.
- Flow control at both connection and stream level, including `SETTINGS_INITIAL_WINDOW_SIZE` retroactive adjustment with signed 32-bit overflow detection.
- SETTINGS negotiation: synchronous ACK timing, `SETTINGS_TIMEOUT`, validation of each parameter's legal range.
- Two-phase GOAWAY: graceful drain window before socket close.
- CONTINUATION interleaving: only CONTINUATION frames on the same stream accepted between HEADERS and END_HEADERS; anything else is a `PROTOCOL_ERROR`.
- Pseudo-header validation: required set per direction, order rule, lowercase header names, `:path` non-empty for non-CONNECT, `:authority` / `Host` consistency.
- Connection-specific headers rejected (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`).
- Error codes per §7 plus per-type stream-id validation on receive.
- CONNECT tunnel mode (§8.3): a 2xx response promotes the stream to a raw byte tunnel; `END_STREAM` is half-close, trailers rejected, CL/TE rejected.

### HPACK (RFC 7541)

- Static table (61 entries), dynamic table (FIFO eviction), Huffman coding, variable-length integer encoding.
- `SETTINGS_HEADER_TABLE_SIZE` propagated to both encoders; decoder enforces that any size update is `≤` the peer-advertised cap and that size updates appear only at the start of a header block.
- Huffman decoder rejects an embedded EOS symbol and rejects padding that isn't strictly a prefix of `11…1`.
- Encode and decode paths use precomputed, shared tables (`persistent_term`) initialized at module load.

### TLS

- ALPN `h2` required on the client, advertised on the server.
- TLS 1.2 and 1.3.
- SNI carried automatically from the client hostname.

### API surface

Public module `h2`:

```erlang
%% Client
h2:connect/2,3
h2:wait_connected/1,2
h2:request/2,3,4,5
h2:send_data/3,4
h2:send_trailers/3
h2:cancel/2,3
h2:set_stream_handler/3,4
h2:unset_stream_handler/2
h2:goaway/1,2
h2:close/1
h2:controlling_process/2

%% Server
h2:start_server/2,3
h2:stop_server/1
h2:server_port/1
h2:send_response/4

%% Inspection
h2:get_settings/1
h2:get_peer_settings/1
```

See the README for usage snippets and `src/h2.erl` for full edoc.

### Events to the owner process

```erlang
{h2, Conn, connected}
{h2, Conn, {response, StreamId, Status, Headers}}
{h2, Conn, {data, StreamId, Data, EndStream}}
{h2, Conn, {trailers, StreamId, Headers}}
{h2, Conn, {stream_reset, StreamId, ErrorCode}}
{h2, Conn, {goaway, LastStreamId, ErrorCode}}
{h2, Conn, {closed, Reason}}
```

Identical shape to `quic_h3` so application code that dispatches on protocol events can be shared between h2 and h3.

## Intentionally out of scope

- **Server push (§8.2)** — deprecated by browsers, removed from HTTP/3.
- **Stream priorities (§5.3)** — deprecated by RFC 9218 (Extensible Priorities); not implemented and not announced.
- **HTTP/2 cleartext upgrade (§3.2)** — this release is ALPN-only. Starting an h2 connection over prior knowledge TCP is supported (`transport => tcp`), but `Upgrade: h2c` from an HTTP/1.1 request is not.
- **Alt-Svc advertisement** — library concern, leave to the caller.
- **Extended CONNECT / RFC 8441** — the `:protocol` pseudo-header and the `SETTINGS_ENABLE_CONNECT_PROTOCOL` setting are announced but the handshake for WebSocket-over-h2 / WebTransport is not implemented yet.

## Internal modules

Useful to know when extending or debugging:

| Module | Role |
|---|---|
| `h2_connection` | `gen_statem` owning the socket; one process per connection. |
| `h2_server` | TLS listener supervisor + acceptor pool, dispatches accepted sockets to `h2_connection` in server mode. |
| `h2_frame` | Pure frame encode/decode with per-type stream-id 0 and size validation. |
| `h2_hpack` | HPACK context type, encode/decode, size updates, Huffman. |
| `h2_settings` | Typed settings map, encode/decode/validate, parameter defaults. |
| `h2_error` | HTTP/2 error code ↔ atom ↔ format-string mapping. |

## Testing

- `rebar3 eunit` — 286 unit tests and 800 PropEr properties across frame/HPACK/settings/varint.
- `rebar3 ct` — 32 Common Test cases: RFC compliance, client/server round-trips, CONNECT tunnel, API-parity with `quic_h3`, error paths.
