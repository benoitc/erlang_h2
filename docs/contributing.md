# Contributing

This page tells you how to change `h2` and prove the change is right. Read it
before your first patch. It applies to people and to coding agents alike;
agents also follow [agents.md](agents.md). If you have not read
[Architecture](architecture.md) yet, start there.

## Set up

You need Erlang/OTP and rebar3. The interop suites use external tools and
skip cleanly when a tool is missing, except h2spec:

```bash
brew install summerwind/h2spec/h2spec   # macOS; Linux: the release tarball
brew install grpcurl curl               # optional: gRPC and GOAWAY interop
pip install grpcio                      # optional: gRPC client interop
```

## Checks to run before every commit

CI runs the same commands and fails on any of them.

```bash
rebar3 compile      # warnings are errors
rebar3 eunit        # unit, raw-socket behaviour tests, PropEr properties
rebar3 ct           # compliance, robustness, h2spec, gRPC and curl interop
rebar3 xref
rebar3 dialyzer
rebar3 ex_doc       # the docs must build
```

Run one module or one suite while you work:

```bash
rebar3 eunit --module=h2_reset_notify_tests
rebar3 ct --suite=test/h2_compliance_SUITE
```

## Changing protocol behaviour

A protocol change is not done when the happy path works. Before you open a
pull request, do these three things. The full checklist is in
[.agents/skills/protocol-change-review/SKILL.md](https://github.com/benoitc/erlang_h2/blob/main/.agents/skills/protocol-change-review/SKILL.md).

1. **Compliance.** Cite the section next to each rule you enforce, for example
   `RFC 9113 §6.9.2`. Add a test for the accepted case and one for the
   rejected case.
2. **Current specification.** Check on the IETF datatracker that the RFC or
   draft you cite is the latest. Drafts change wire values between revisions.
3. **Safety.** Go through the abuse classes in
   [Architecture](architecture.md#limits-against-a-hostile-peer) and make sure
   the peer cannot grow any state without a bound.

## Writing a test

Most behaviour tests drive a **raw peer**: a `gen_tcp` socket that sends
frames built with `h2_frame` and `h2_hpack`, and asserts the exact frames
that come back. Copy the helpers from a recent file such as
`test/h2_reset_notify_tests.erl` (`with_raw_client/1` against an `h2` server,
`with_raw_server/2` against an `h2` client).

Two rules:

- **Show the test fails first.** Run the new test on a `git worktree` at the
  merge base, not with `git stash`:

  ```bash
  git worktree add /tmp/h2-base main
  cp test/my_new_tests.erl /tmp/h2-base/test/
  (cd /tmp/h2-base && rebar3 eunit --module=my_new_tests)   # must fail
  git worktree remove --force /tmp/h2-base
  ```

- **Test private functions inside their module**, under `-ifdef(TEST)`. Do
  not export a function only for a test.

If an existing test encodes behaviour the RFC forbids, follow the RFC, change
the test, and say so in the pull request.

## Where to change what

Section names are the banner comments in `src/h2_connection.erl`.

| If you want to change | Start in | Tests to run and extend |
| --- | --- | --- |
| Public calls, options, their types | `src/h2.erl` | `h2_compliance_SUITE` (api_parity group) |
| Listening, accepting, serving a socket you accepted | `src/h2.erl`, `src/h2_listener.erl` | `h2_listener_*_tests`, `h2_serve_socket_tests` |
| Connection start, preface, SETTINGS exchange | `h2_connection`: the state sections, Settings Handling | `h2_settings_flood_tests`, `h2_peer_settings_notify_tests`, `h2_ext_settings_tests` |
| Request and response header rules, trailers, tunnels | `h2_connection`: Headers Handling | `h2_compliance_SUITE`, `h2_no_content_tests`, `h2_reset_notify_tests` |
| Receiving DATA, body length, receive windows | `h2_connection`: Data Frame Handling | `h2_conn_window_tests`, `h2_max_body_size_tests` |
| Sending responses, data, trailers, send windows | `h2_connection`: Send Operations | `h2_coalesce_tests`, `h2_grpc_tests`, `h2_grpc_frame_tests` |
| Which process receives an event | `dispatch_stream_event/3` | `h2_grpc_tests`, `h2_reset_notify_tests` |
| Stream table, counts, closing | `h2_connection`: Stream Management | `h2_stream_count_tests`, `h2_stream_available_tests` |
| Limits against a hostile peer | the macros at the top of `h2_connection`, `sent_rst/3`, `bump_flood_counter/2` | `h2_made_you_reset_tests`, `h2_settings_flood_tests`, `h2_robustness_SUITE` |
| GOAWAY and shutdown | `h2_connection`: goaway_sent, goaway_received, closing | `h2_goaway_drain_tests`, `h2_goaway_cancel_tests`, `h2_goaway_interop_SUITE`, `h2_tls_close_tests` |
| Frame layout and frame-level validation | `src/h2_frame.erl` | in-module tests, `h2_prop_tests` |
| Header compression | `src/h2_hpack.erl` | `h2_hpack_compliance_tests`, `h2_prop_tests` |
| Capsules and extension settings | `src/h2_capsule.erl`, `src/h2_varint.erl`, `src/h2_settings.erl` | in-module tests, `h2_ext_settings_tests`, `h2_report_peer_settings_tests` |

## If you want to...

**Add or tighten a protocol rule.** Find where the frame is handled (the
table above). Decide whether a violation is a stream error or a connection
error; the RFC says which. For a stream error call `reset_stream/3`, never
`sent_rst/3` plus your own cleanup: `reset_stream/3` also tells the handler
and closes the stream. For a connection error return
`{error, ErrorCode, State}` from the frame handler. Add an accept test and a
reject test.

**Add an event for the owner or a stream handler.** Send it through
`dispatch_stream_event/3` so it is routed and buffered like the others. List
it in [features.md](features.md) and the README events table. The event
shapes match `quic_h3`; check with the maintainer before you add one that
HTTP/3 cannot mirror.

**Add an option to `h2:connect/3` or `h2:start_server/2`.** Add it to the
`connect_opts()` or `server_opts()` type in `src/h2.erl` and to the
`maps:with/2` list in `start_connection/3` (for a server, to
`conn_opts/1`, which the built-in server and `serve_socket/2` share), then read it in `h2_connection:init/1`. Give it a
default that keeps today's behaviour.

**Add a SETTINGS parameter.** Known parameters are named in
`src/h2_settings.erl` and `include/h2.hrl`. An extension setting needs no
code: callers pass it under its raw 16-bit id.

**Add a limit against a new abuse pattern.** Count the event per connection
and per second next to the existing counters (`bump_flood_counter/2` for
frames the peer sends, `sent_rst/3` for resets it makes you send). Past the
cap, return `{error, enhance_your_calm, State}`. Add a raw-socket test that
drives the attack and asserts the connection ends. A real vulnerability also
gets a `Security` entry in the CHANGELOG and a GitHub Security Advisory.

**Follow one request through the connection.** Trace the state callbacks:

```erlang
dbg:tracer(), dbg:p(Conn, [c, timestamp]),
dbg:tpl(h2_connection, connected, 3, []),
dbg:tpl(h2_connection, handle_frame, 3, []).
```

Frames enter at `handle_data/3`, are decoded in `process_frames/2`, and are
dispatched by `handle_frame/3`.

**Extend the public API.** Add the function to `src/h2.erl` with a spec and
a doc comment, and keep the call into `h2_connection` thin. New behaviour
must be additive and off by default. Existing tests must pass unedited.

**Run the interop suites.** `h2_interop_SUITE` runs h2spec against the
server over TLS and cleartext. `h2_grpc_interop_SUITE` drives the server
with grpcurl, `h2_grpc_client_interop_SUITE` drives a grpc-python server
with the `h2` client, and `h2_goaway_interop_SUITE` uses curl. Logs are under
`_build/test/logs/`.

## Pull requests and releases

- One issue, one pull request. Docs and the CHANGELOG entry go in the same
  pull request as the code.
- The description states what was wrong and why it matters, the solution in a
  few lines, and any breaking change. Do not walk through the diff.
- CHANGELOG entries are short and in plain English: what was wrong or what is
  new, and what it means for the user. No code, no internal names.
- No breaking changes without the maintainer's agreement. Other projects
  depend on `h2`, `h2_capsule`, `h2_varint` and `h2_error`.
