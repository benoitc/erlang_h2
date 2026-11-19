# Inside h2_connection

This page is a reading guide to `src/h2_connection.erl`, the state machine
that holds most of the protocol. Read it before you change that file. It
assumes you know the model in [Architecture](../architecture.md).

The file is large because one process has to see every frame of a
connection. It is easier to work in once you know that a small set of
functions carries the rules, and that the rest calls them.

## Layout

The file is cut into sections by banner comments. In order:

| Section | What is there |
| --- | --- |
| API Functions | The exported calls. Each is a thin `gen_statem:call` or cast. `init/1` reads the options. |
| State: preface, settings, connected, goaway_sent, goaway_received, closing | One function per connection state. They receive socket data, API calls and timers, and delegate. |
| Data Handling | `handle_data/3` appends socket bytes to the buffer; `process_frames/2` decodes frames one at a time and enforces the reset budget. |
| Frame Handling | `handle_frame/3`, one clause per frame type. |
| Settings Handling | Applying the peer's SETTINGS and our own once acknowledged. |
| Headers Handling | Header blocks and CONTINUATION, then what to do with a request, a response or trailers once `h2_headers` has judged them: create the stream, tell the owner, or reset. |
| Data Frame Handling | DATA frames, body-length checks, receive windows, WINDOW_UPDATE. |
| Send Operations | Requests, responses, data and trailers going out; send buffers; callers blocked on a full window. |
| Common Call Handling | Calls that work in several states (`handle_stream_call/3`, `handle_call_common/4`, `handle_common/4`). |
| Stream Management | The stream table, the active-stream counters and closing. |
| Frame Sending | Writing frames to the socket; `sent_rst/3` and the reset budget. |
| Utilities | Socket helpers, timers, owner notification. |

## What lives outside this file

Two parts need no connection state and are separate modules. Change them
there, not here.

| Module | What it does | Why it is separate |
| --- | --- | --- |
| `h2_headers` | Judges a decoded header list (request, response, trailers, outbound) and reads it (status, content length, method and path). | It is a pure function of the headers. `h2_connection` only decides what a verdict means for the stream. |
| `h2_closed_streams` | Remembers how recently closed streams ended, within two fixed bounds. | The bounds are a safety property and are tested on their own. `close_stream/3` is the only writer. |

## How a frame is handled

1. A state function gets `{tcp, Socket, Data}` or `{ssl, Socket, Data}` and
   calls `handle_data/3`.
2. `process_frames/2` decodes the next frame with `h2_frame:decode/2`.
3. `handle_frame/3` handles it and returns one of:
   - `{ok, NextStateName, State}`: carry on.
   - `{error, ErrorCode, State}`: a connection error. The caller sends GOAWAY
     and moves to `closing`.
4. `process_frames/2` loops until the buffer holds no complete frame, then
   re-arms the socket.

A frame handler does not stop the process or write the GOAWAY for an error
itself. It returns the error and lets `process_frames/2` do it, so the last
stream id and the state change are right every time.

## Functions to use, not to copy

These are the choke points. Each exists because the same rule was once
written out in several places and the copies drifted apart.

| Function | Use it to | What it guarantees |
| --- | --- | --- |
| `reset_stream/3` | reset a stream because of what the peer sent | the handler or owner is told once, RST_STREAM is sent and counted, the stream is closed |
| `sent_rst/3` | send an RST_STREAM the peer caused, when `reset_stream/3` does not fit (the stream is unknown or already closed) | the reset counts against the MadeYouReset budget |
| `send_rst_stream/3` | send an RST_STREAM the application asked for (`h2:cancel`), or a pre-admission REFUSED_STREAM | not counted: these are not abuse |
| `dispatch_stream_event/3` | deliver any per-stream event | handler, buffer or owner is chosen in one place; buffered events are replayed in order |
| `put_stream/3` | store a stream record | the active-stream counters stay exact |
| `close_stream/3` | close a stream | blocked senders are released, the close reason is remembered for late frames (`h2_closed_streams`), old records are evicted |
| `bump_flood_counter/2` | count a frame the peer can send cheaply | the per-second cap for that frame type |
| `check_outbound/3` | check a header block before you send it (request, response or trailers) | it is validated first, then held to the peer's header list limit, and nothing is encoded if it is refused |
| `send_failed/3` | end a call whose socket write failed | the caller gets the reason and the connection stops |
| `after_local_end/1`, `close_if_ended/3` | move a stream on after you sent END_STREAM | the same transition on every send path, and the stream is closed once both sides have ended |
| `open_client_stream/6` | send the HEADERS of a new request | the stream is stored and its id taken only if the write succeeded |
| `notify_owner/2` | send a connection event | one place that knows who the owner is |

If you find yourself writing `send_rst_stream` followed by `close_stream`,
you want `reset_stream/3`.

The calls that send a header block (`handle_send_request/6`,
`handle_send_request_headers/5`, `handle_send_response/6`, `handle_respond/6`)
each keep their own checks, because the order in which errors are reported is
part of their contract and `test/h2_send_paths_tests.erl` pins it. Only the
steps that are identical are shared. The small helpers are inlined by the
compiler (see the `-compile` attribute at the top of the file), so using them
costs nothing on the request path.

## Things that are easy to break

- **Every header block must be decoded**, even for a stream you refuse or
  have already reset. HPACK state is shared by the whole connection; skipping
  a block desynchronises the tables and the next request fails with
  COMPRESSION_ERROR. See `reject_header_block/5`.
- **A stream is a tunnel only after the 2xx.** `tunnel` is set when the
  response is sent (server) or received (client), never when the CONNECT
  request is seen.
- **Closed streams still matter.** A frame on a stream that ended with
  END_STREAM is a connection error; on a stream that was reset it is a stream
  error. `close_stream/3` records which one.
- **REFUSED_STREAM for too many concurrent streams is not counted** against
  the reset budget. A busy, well-behaved client must not be dropped.
- **A server answers before the SETTINGS exchange ends.** Calls a request
  handler can make must work in the `settings` state as well as in
  `connected`.
- **`goaway_sent` and `goaway_received` are sticky.** Frame handlers return
  `connected` as the next state out of habit; `next_frame_state/2` keeps the
  connection where it is.

## Tests

Private functions are tested at the bottom of the module under
`-ifdef(TEST)`. Behaviour is tested from outside with raw-socket peers; the
table in [Contributing](../contributing.md#where-to-change-what) says which
file covers which area.
