# h2

HTTP/2 client and server for Erlang/OTP.

- Full **RFC 7540 / RFC 9113** protocol (frames, streams, flow control, SETTINGS negotiation, GOAWAY, CONTINUATION, malformed-message enforcement).
- **RFC 7541** HPACK with static + dynamic tables and Huffman coding.
- **RFC 7540 §8.3** CONNECT tunnel mode for bidirectional byte streams.
- **RFC 8441** Extended CONNECT (`:protocol` pseudo-header) for bootstrapping WebSockets and similar protocols over HTTP/2.
- ALPN `h2` over TLS 1.2+ by default; cleartext (`h2c` over plain TCP) also supported.
- Owner-process event messages (`{h2, Conn, Event}`) mirroring the [`quic_h3`](https://github.com/benoitc/erlang_quic) HTTP/3 API so cross-protocol code stays symmetric.

## Install

Add to `rebar.config`:

```erlang
{deps, [
    {h2, "0.2.0", {git, "https://github.com/benoitc/erlang_h2.git", {tag, "0.2.0"}}}
]}.
```

Requires Erlang/OTP 24+.

## Client

```erlang
{ok, Conn} = h2:connect("example.com", 443),
{ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"example.com">>}]),
receive
    {h2, Conn, {response, StreamId, Status, _Headers}} ->
        io:format("status: ~p~n", [Status])
end,
receive
    {h2, Conn, {data, StreamId, Body, true}} ->
        io:format("body: ~p~n", [Body])
end,
ok = h2:close(Conn).
```

Messages delivered to the owner process:

| Message | Meaning |
|---|---|
| `{h2, Conn, connected}` | handshake + SETTINGS exchange complete |
| `{h2, Conn, {response, StreamId, Status, Headers}}` | final response headers (2xx–5xx) |
| `{h2, Conn, {informational, StreamId, Status, Headers}}` | 1xx interim response (100/103/…) |
| `{h2, Conn, {data, StreamId, Data, EndStream}}` | response body fragment (an empty final frame marks end-of-stream for body-less responses) |
| `{h2, Conn, {trailers, StreamId, Headers}}` | response trailers |
| `{h2, Conn, {stream_reset, StreamId, ErrorCode}}` | peer sent RST_STREAM |
| `{h2, Conn, {goaway, LastStreamId, ErrorCode}}` | peer is shutting down |
| `{h2, Conn, {closed, Reason}}` | connection closed |

Options to `h2:connect/3`:

```erlang
#{transport    => ssl | tcp,            %% default: ssl
  ssl_opts     => [ssl:tls_client_option()],
  verify       => verify_peer | verify_none,
  cacerts      => [binary()],
  settings     => h2_settings:settings(),
  timeout      => timeout()}
```

Send a request body in chunks:

```erlang
{ok, Sid} = h2:request(Conn, <<"POST">>, <<"/upload">>, Headers, false),
ok = h2:send_data(Conn, Sid, Chunk1, false),
ok = h2:send_data(Conn, Sid, Chunk2, true).   %% last chunk: EndStream = true
```

## Server

```erlang
Handler = fun(Conn, StreamId, <<"GET">>, <<"/">>, _Headers) ->
    h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
    h2:send_data(Conn, StreamId, <<"Hello HTTP/2!">>, true)
end,

{ok, Server} = h2:start_server(8443, #{
    cert    => "server.pem",
    key     => "server.key",
    handler => Handler
}),

Port = h2:server_port(Server),
%% ... later ...
ok = h2:stop_server(Server).
```

Options to `h2:start_server/2,3`:

```erlang
#{cert                    := binary() | string(),
  key                     := binary() | string(),
  cacerts                 => [binary()],
  handler                 := fun((Conn, StreamId, Method, Path, Headers) -> any()),
  settings                => h2_settings:settings(),
  acceptors               => pos_integer(),       %% default: schedulers
  transport               => ssl | tcp,           %% default: ssl
  enable_connect_protocol => boolean()}           %% RFC 8441, default: false
```

A module handler (`handler => {Mod, Args}`) is also supported; `Mod:handle_request/5` receives the same arguments.

## CONNECT tunnels (RFC 7540 §8.3)

Open a bidirectional byte tunnel through an h2 proxy:

```erlang
%% Client
{ok, Conn} = h2:connect(ProxyHost, ProxyPort),
{ok, Sid}  = h2:request(Conn, [
    {<<":method">>, <<"CONNECT">>},
    {<<":authority">>, <<"target.example.com:443">>}
]),
receive {h2, Conn, {response, Sid, 200, _}} -> ok end,
ok = h2:send_data(Conn, Sid, <<"raw bytes">>, false),
receive {h2, Conn, {data, Sid, Reply, _}} -> Reply end.
```

Server handler establishes the tunnel by replying 2xx, then echoes / forwards bytes via `set_stream_handler/3`:

```erlang
fun(Conn, Sid, <<"CONNECT">>, _, _Headers) ->
    h2:send_response(Conn, Sid, 200, []),
    h2:set_stream_handler(Conn, Sid, self()),
    tunnel_loop(Conn, Sid)
end.
```

Tunnel semantics: DATA frames carry raw bytes (no body-length enforcement), `END_STREAM` is a half-close, trailers are rejected, and `Content-Length` / `Transfer-Encoding` on the 2xx response are rejected.

## Extended CONNECT (RFC 8441)

Bootstrap WebSockets (or any protocol) over an HTTP/2 stream. Server opts in:

```erlang
{ok, Server} = h2:start_server(8443, #{
    cert => "server.pem",
    key => "server-key.pem",
    handler => Handler,
    enable_connect_protocol => true   %% advertises SETTINGS_ENABLE_CONNECT_PROTOCOL=1
}).
```

Client uses the `protocol` opt; `:scheme`, `:path`, `:authority` are required:

```erlang
{ok, Conn} = h2:connect("localhost", 8443),
{ok, Sid}  = h2:request(Conn, [
    {<<":method">>, <<"CONNECT">>},
    {<<":scheme">>, <<"https">>},
    {<<":path">>, <<"/chat">>},
    {<<":authority">>, <<"localhost">>}
], #{protocol => <<"websocket">>}),
receive {h2, Conn, {response, Sid, 200, _}} -> ok end,
ok = h2:send_data(Conn, Sid, FrameBytes, false).
```

If the peer never advertised the setting, `h2:request/3` returns `{error, extended_connect_disabled}`. Server handlers see `:protocol` in the request `Headers` argument. Tunnel semantics (no body length, no trailers) apply once the 2xx is sent.

## Modules

| Module | Purpose |
|---|---|
| `h2` | Public API (client + server). |
| `h2_connection` | `gen_statem` per-connection state machine. |
| `h2_server` | TLS listener + acceptor pool. |
| `h2_frame` | Frame encode/decode. |
| `h2_hpack` | HPACK encoder/decoder. |
| `h2_settings` | SETTINGS encode/decode/validate. |
| `h2_error` | Error code mappings. |

## Build and test

```bash
rebar3 compile
rebar3 eunit          # 310 tests + 800 PropEr properties
rebar3 ct             # 54 compliance + API-parity + tunnel cases
rebar3 dialyzer       # clean
rebar3 xref           # clean
rebar3 ex_doc         # HTML docs
```

## Status

Production-oriented: spec-correct and deterministic under the in-tree CT suite. Intentionally out of scope:

- Server push (§8.2) — deprecated and rarely useful.
- Stream priorities (§5.3) — deprecated by RFC 9218.
- Alt-Svc and HTTP/2 cleartext upgrade (§3.2) — ALPN-only in this release.

## License

Apache License 2.0
