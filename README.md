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
    {h2, "0.3.0", {git, "https://github.com/benoitc/erlang_h2.git", {tag, "0.3.0"}}}
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

`h2:start_server/2` starts the listener under the `h2` application's supervision tree, so make sure the application is started first:

```erlang
ok = application:ensure_started(h2).
```

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

### Scaling the acceptor pool

Each accepted socket runs its own `h2_connection` gen_statem, so concurrency on established connections scales with BEAM schedulers. The `acceptors` opt only sizes the pool of processes blocked in `ssl:transport_accept` / `gen_tcp:accept` on the shared listen socket — raise it when the incoming connection rate (not in-flight traffic) is the bottleneck:

```erlang
h2:start_server(8443, #{cert => ..., key => ..., handler => ...,
                        acceptors => 100}).
```

Default is `erlang:system_info(schedulers)` (one per core). 100 is a good ceiling for high connection-rate workloads; going higher rarely helps. Complementary knobs: kernel `somaxconn` / `tcp_max_syn_backlog`, OS-level SSL session cache, and a `handler` that spawns per request (the built-in server loop already does).

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

## Using with Ranch

The built-in `h2:start_server/2` runs its own acceptor pool. To plug into an existing Ranch listener instead, use `h2_connection` directly — it's a normal `gen_statem` you hand a socket to. A minimal Ranch protocol module:

```erlang
-module(h2_ranch_protocol).
-behaviour(ranch_protocol).
-export([start_link/3]).

start_link(Ref, Transport, Opts) ->
    {ok, spawn_link(fun() -> init(Ref, Transport, Opts) end)}.

init(Ref, Transport, #{handler := Handler} = Opts) ->
    {ok, Socket}  = ranch:handshake(Ref),
    TransportMod  = case Transport of ranch_ssl -> ssl; ranch_tcp -> gen_tcp end,
    ConnOpts      = #{settings => maps:get(settings, Opts, #{}),
                      enable_connect_protocol => maps:get(enable_connect_protocol, Opts, false)},
    {ok, Conn}    = h2_connection:start_link(server, Socket, self(), ConnOpts),
    ok            = TransportMod:controlling_process(Socket, Conn),
    _             = h2_connection:activate(Conn),
    server_loop(Conn, Handler).

server_loop(Conn, Handler) ->
    receive
        {h2, Conn, {request, Sid, M, P, H}} ->
            spawn(fun() -> Handler(Conn, Sid, M, P, H) end),
            server_loop(Conn, Handler);
        {h2, Conn, {closed, _}} -> ok;
        _                        -> server_loop(Conn, Handler)
    end.
```

Wire it up:

```erlang
{ok, _} = ranch:start_listener(my_h2, ranch_ssl,
    #{socket_opts => [{port, 8443},
                      {certfile, "cert.pem"}, {keyfile, "key.pem"},
                      {alpn_preferred_protocols, [<<"h2">>]}]},
    h2_ranch_protocol,
    #{handler => fun my_app:handle/5}).
```

Ranch owns draining, acceptor-pool sizing, and metrics; `h2_connection` handles h2 semantics. Public primitives used: `h2_connection:start_link/4` and `h2_connection:activate/1`.

## Coexisting with HTTP/1.1

This library is HTTP/2-only. Where you need HTTP/1.1 too, the pattern is always "different library, same socket boundary".

**Client fallback.** `h2:connect/2,3` surfaces ALPN mismatches explicitly — no silent fall-through to assumed-h2 (RFC 9113 §3.3):

```erlang
case h2:connect(Host, 443) of
    {ok, Conn}                               -> h2_flow(Conn);
    {error, {alpn_mismatch, <<"http/1.1">>}} -> http1_flow(Host);
    {error, alpn_not_negotiated}             -> http1_flow(Host);
    Err                                      -> Err
end.
```

**Dual-stack server.** Advertise both protocols on the listener and dispatch by ALPN result. With the Ranch snippet above:

```erlang
init(Ref, ranch_ssl, Opts) ->
    {ok, Socket} = ranch:handshake(Ref),
    case ssl:negotiated_protocol(Socket) of
        {ok, <<"h2">>}       -> start_h2(Socket, Opts);
        {ok, <<"http/1.1">>} -> start_http1(Socket, Opts);   %% e.g. cowboy / elli
        _                    -> ssl:close(Socket)
    end.
```

Listener `alpn_preferred_protocols` becomes `[<<"h2">>, <<"http/1.1">>]`. One port, TLS picks per connection.

**Cleartext `Upgrade: h2c` from HTTP/1.1.** Deprecated by RFC 9113 and not supported. Use prior-knowledge h2c instead — both peers agree out of band that the connection is plaintext h2:

```erlang
{ok, Conn}   = h2:connect(Host, Port, #{transport => tcp}).
{ok, Server} = h2:start_server(Port, #{transport => tcp, handler => Handler}).
```

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
rebar3 ct             # 81 compliance + 6 h2spec interop cases
rebar3 dialyzer       # clean
rebar3 xref           # clean
rebar3 ex_doc         # HTML docs
```

## Interop

External-peer interop tests live in `test/h2_interop_SUITE.erl` and drive
the server from [h2spec](https://github.com/summerwind/h2spec). Install
h2spec locally, then:

```bash
# macOS
brew install summerwind/h2spec/h2spec
# Linux: download a release tarball from
# https://github.com/summerwind/h2spec/releases

rebar3 ct --suite=test/h2_interop_SUITE
```

Without h2spec on `PATH` the suite skips cleanly. The generic and HPACK
groups are run in observe mode — failures are logged with full output for
triage rather than treated as hard failures. Library-level conformance
(which does not need h2spec) stays in `h2_compliance_SUITE`.

## Status

Production-oriented: spec-correct and deterministic under the in-tree CT suite. Intentionally out of scope:

- Server push (§8.2) — deprecated and rarely useful.
- Stream priorities (§5.3) — deprecated by RFC 9218.
- Alt-Svc and HTTP/2 cleartext upgrade (§3.2) — ALPN-only in this release.

## License

Apache License 2.0
