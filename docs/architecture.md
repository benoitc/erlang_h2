# Architecture

This page gives you the mental model of `h2` before you read the source. Read
it when you are about to change the library, debug a connection, or decide
whether a behaviour belongs in `h2` or in your own code. If you only want to
use the library, the [README](../README.md) is enough.

## One process per connection

Each HTTP/2 connection is one `h2_connection` process, a `gen_statem` that
owns the socket. It exists so that everything the protocol shares across
streams (the HPACK tables, the connection flow-control window, the stream
table, the frame order on the wire) has a single writer and needs no locks.

Everything else talks to that process:

- The **owner** is the process that started the connection. It receives
  `{h2, Conn, Event}` messages.
- A **stream handler** is a process registered for one stream with
  `h2:set_stream_handler/3,4` or `#{handler => Pid}`. It receives that
  stream's events instead of the owner.
- A **request handler** is the function you give to `h2:start_server/2`. The
  built-in server runs it in a new process for every request.

Callers never touch the socket. They call `h2:send_response/4`,
`h2:send_data/4` and so on, which are synchronous calls into the connection
process.

## Who owns what on the server

```
h2_sup
  └─ h2_listener          one per h2:start_server/2: owns the listen socket
       └─ acceptors       run the accept loop that lives in h2.erl
            └─ connection owner     one per accepted socket (h2.erl)
                 ├─ h2_connection   the state machine, owns the socket
                 └─ request handler one process per request
```

The accept loop and the per-connection owner loop are in `h2.erl`, not in
`h2_listener`. That is deliberate: `h2:serve_socket/2` is public and runs the
same owner loop in a process **you** own. You need it when you accept
connections yourself, for example a listener that reads the ALPN result and
hands the socket to HTTP/2 or HTTP/1.1. `h2_listener` only keeps the listen
socket and the acceptors alive, so a short-lived caller of `start_server/2`
does not take the listener down with it.

## Connection states

```
preface ──► settings ──► connected ──► goaway_sent ─────► (stopped)
               │             │              ▲
               │             └──► goaway_received ──► closing ──► (stopped)
               └──────────────────────────┘
                  goaway/1 before the peer's SETTINGS ACK
```

- `preface`: waiting for the socket to be handed over, then for the first
  bytes from the peer.
- `settings`: our SETTINGS are sent and the peer's ACK has not arrived. A
  server already dispatches requests here, because clients send requests
  right after their preface (RFC 9113 §3.4). Response calls and `goaway` work
  in this state.
- `connected`: the normal state. The owner gets `connected`.
- `goaway_sent`: we asked for a graceful shutdown. Two GOAWAY frames go out
  100 ms apart; streams already open finish, bounded by `goaway_timeout`.
- `goaway_received`: the peer is leaving. Our open streams may finish.
- `closing`: a connection error was sent or the peer closed; the process is
  about to stop.

A frame handled in `goaway_sent` or `goaway_received` never moves the
connection back to `connected`.

## Life of a request on the server

```
socket ─► h2_frame:decode ─► handle_frame ─► headers validated
                                                  │
                          owner gets {request, Sid, Method, Path, Headers}
                                                  │
                                    handler process is spawned
                                                  │
        DATA frames ─► {data, Sid, Bin, Fin} ─► stream handler, or buffered
                                                  │
     h2:send_response / send_data / respond ─► h2_connection ─► socket
```

A stream is created when its HEADERS arrive, lives in the connection's stream
table while it is `open` or half closed, and is kept for a while after it
closes. The connection remembers the last 100 closed streams in full and the
close reason of the last 10,000, because RFC 9113 §5.1 treats a late frame
differently depending on how the stream ended.

## Where an event goes

Every per-stream event (`response`, `informational`, `data`, `trailers`,
`stream_reset`) goes through one function, `dispatch_stream_event/3`:

1. A stream handler is registered: it gets the event.
2. The stream was created with `defer => true`: the event is buffered.
3. Client connection, no handler: the owner gets the event.
4. Server connection, no handler: the event is buffered.

Buffered events are replayed in order when a handler registers. This is why a
server handler can call `set_stream_handler` after the request body has
started to arrive and lose nothing.

`goaway` and `closed` are connection events. They go to the owner and to
every stream handler.

The event shapes match `quic_h3`, so code that handles protocol events can be
shared between HTTP/2 and HTTP/3. Keep that in mind before you add or change
an event.

## Stream errors and connection errors

A **stream error** ends one stream: `h2` sends RST_STREAM, tells the stream's
handler or owner with `stream_reset`, and closes the stream. All of that is
`reset_stream/3`. A **connection error** ends everything: `h2` sends GOAWAY
with the error code and moves to `closing`.

Which one applies is set by the RFC, rule by rule. When you add a rule, cite
the section next to the code.

## Flow control

HTTP/2 has a window per stream and one per connection, in each direction.

- **Receiving.** By default (`auto`) the connection sends WINDOW_UPDATE as
  soon as a window falls below half, so a peer can always send. With
  `flow_control => manual` the stream window is refilled only when your code
  calls `h2:consume/3`, which is how a slow consumer pushes back on the peer.
- **Sending.** Data that does not fit the peer's window is buffered on the
  stream and flushed when WINDOW_UPDATE arrives. `h2:send_data/5` with
  `#{block => Timeout}` makes the caller wait instead.

A CONNECT stream becomes a **tunnel** only when its 2xx response is sent or
received. From then on DATA is opaque bytes, body-length rules do not apply,
and trailers are a stream error.

## Limits against a hostile peer

A peer can reach this code without authentication, so every per-peer resource
has a bound. They are macros at the top of `h2_connection.erl`.

| Limit | Value | Defends against |
| --- | --- | --- |
| RST_STREAM received per second | 100 | Rapid Reset (CVE-2023-44487) |
| Resets we send because of the peer, per second | 100 | MadeYouReset (CVE-2025-8671) |
| SETTINGS received per second | 20 | SETTINGS flood (CVE-2019-9515) |
| PING received per second | 20 | PING flood |
| Raw header block before decoding | 256 KiB | CONTINUATION flood (CVE-2024-27316) |
| Closed streams remembered | 100 records, 10,000 reasons | unbounded memory |
| Request or response body | `max_body_size` option | unbounded bodies |

Past a per-second limit the connection sends GOAWAY with ENHANCE_YOUR_CALM.

## What is public

| Module | Status |
| --- | --- |
| `h2` | The API. Stable. |
| `h2_capsule`, `h2_varint`, `h2_error` | Called directly by other projects (erlang-webtransport). Treat a change as an API change. |
| `h2_connection`, `h2_frame`, `h2_hpack`, `h2_settings`, `h2_listener` | Internal. Reach them through `h2`. |
| `h2_server`, `h2_client` | Standalone command-line tools (escripts). The library does not use them. |

WebTransport is not implemented here. `h2` supplies what a WebTransport
implementation needs (Extended CONNECT, extension SETTINGS, the peer's
SETTINGS, the TLS version, the capsule codec), and the session layer lives in
erlang-webtransport.

## Read next

- [Contributing](contributing.md): the checks to run and where to change what.
- [Inside h2_connection](internals/connection.md): how the state machine file
  is laid out.
- [The wire codecs](internals/wire.md): frames, HPACK, settings, capsules.
- [Features](features.md): what is supported, rule by rule.
