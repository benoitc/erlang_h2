# Agents

Instructions for AI coding agents working on this project.

## Project Overview

Pure Erlang HTTP/2 implementation (RFC 9113, formerly RFC 7540) with zero
external runtime dependencies: client, server, HPACK, flow control, GOAWAY,
CONTINUATION handling, gRPC-style bidirectional streaming, and WebTransport /
Extended CONNECT support. Requires Erlang/OTP and rebar3.

## Required Checks

Every change must compile and pass all checks before committing. This matches
what CI gates on (`.github/workflows/`).

```bash
rebar3 compile              # Must compile cleanly (warnings are errors)
rebar3 eunit                # Unit + in-module spec tests + PropEr properties
rebar3 ct                   # Common Test: h2spec interop, compliance, gRPC, robustness
rebar3 xref                 # Cross-reference analysis must pass
rebar3 dialyzer             # Type checking must pass
rebar3 ex_doc               # Docs must build
```

`rebar3 ct` needs `h2spec` installed for the interop suite (`brew install
summerwind/h2spec/h2spec`, or the Linux release tarball); the gRPC interop
suites skip cleanly when `grpcurl` / python `grpcio` are absent.

## Protocol change review

A change to protocol code is not done when it compiles and the happy path works.
Before calling a change done, opening a pull request, or releasing, run the three
checks in the [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md)
skill and state their result in the pull request:

1. **Compliance** — the suites above pass; cite the spec section (e.g. `RFC 9113
   §6.9.2`) for each rule enforced; add both an accept and a reject test; prove a
   new test against a `git worktree` baseline at the merge base, not `git stash`.
2. **Latest related specification** — confirm the governing RFC/draft is current
   (an RFC can be obsoleted, a `draft-ietf-...-NN` revs and wire values change)
   via the IETF datatracker; read the section, note the version and date checked.
3. **Safety** — check the change against the known HTTP/2 abuse classes (Rapid
   Reset, MadeYouReset, HPACK bomb, CONTINUATION flood, SETTINGS/PING floods,
   flow-control stalls, window overflow) and keep every per-peer resource
   bounded. On a real vulnerability fix add a raw-socket regression test, a
   `Security` CHANGELOG entry, and a published GitHub Security Advisory.

## Pull Requests

Work on one issue goes in one pull request. Docs and CHANGELOG entries go in the
same pull request. Keep the description to the intent and the fix in a few lines
plus any breaking changes; do not walk the diff file by file, and do not add a
test-plan section. CHANGELOG entries and release notes are short, plain English —
what was wrong or new and what it means for the user — with no code snippets or
internal detail.

## Skills

Task guides for agents live in `.agents/skills/<name>/SKILL.md`; read the one
that matches the task before starting. `.claude/skills` links to the same
directories, so there is one copy.

- [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md): check
  a change or pull request for compliance, the latest related spec, and safety.

## Build & Development Commands

```bash
rebar3 compile                                       # Build
rebar3 eunit                                         # Run all EUnit tests
rebar3 eunit --module=h2_frame                       # Run one test module
rebar3 eunit --module=h2_prop_tests                  # PropEr properties (run under eunit)
rebar3 ct                                            # Run all Common Test suites
rebar3 ct --suite=test/h2_interop_SUITE              # Run one suite (h2spec interop)
rebar3 xref                                          # Cross-reference analysis
rebar3 dialyzer                                      # Type checking
rebar3 ex_doc                                        # Generate docs
rebar3 as server escriptize                          # Build the h2_server escript
rebar3 as client escriptize                          # Build the h2_client escript
```

## Architecture

### Module Layers

**Public API:** `h2.erl` (client + server API), `h2_client.erl` / `h2_server.erl`
(escript entry points), `h2_listener.erl` (acceptor/listener)

**Connection Management:** `h2_connection.erl` (gen_statem state machine — the
central module; preface → settings → connected → goaway/closing), `h2_sup.erl` /
`h2_app.erl` (OTP app and supervisor)

**Protocol:** `h2_frame.erl` (frame encode/decode), `h2_hpack.erl` (HPACK header
compression, with `include/h2_hpack_huffman.hrl`), `h2_settings.erl` (SETTINGS
encode/decode/validate, incl. extension settings under raw 16-bit ids),
`h2_varint.erl` (variable-length integers), `h2_error.erl` (error codes),
`h2_capsule.erl` (RFC 9297 capsules for WebTransport/Extended CONNECT)

### Supervision Tree

`h2_app` → `h2_sup` (`simple_one_for_one` over `h2_listener`). Each server
listener is a child; accepted connections are `h2_connection` gen_statem
processes started per socket.

### Key Files

- `include/h2.hrl` — protocol constants, frame/setting/error codes, limits
  (`?DEFAULT_INITIAL_WINDOW_SIZE`, `?MAX_WINDOW_SIZE`, flood limits, record defs)
- `include/h2_hpack_huffman.hrl` — HPACK Huffman table
- `docs/features.md` — feature matrix and API reference
- `README.md` — usage and examples

### Connection Model

Connections are `gen_statem` processes (`h2_connection.erl`) that progress
`preface` → `settings` → `connected`, then `goaway_sent` / `goaway_received` /
`closing`. The owner process receives messages like `{h2, Conn, {response,
StreamId, Status, Headers}}`, `{h2, Conn, {data, StreamId, Data, Fin}}`,
`{h2, Conn, {goaway, LastStreamId, ErrorCode}}` and `{h2, Conn, {closed,
Reason}}`. Per-stream handlers can be registered so a per-call process receives
its stream's events directly (gRPC bidi).

### Test Organization

- `test/h2_*_tests.erl` — EUnit (unit, frame vectors, behavioural); internals are
  tested in-module under `-ifdef(TEST)`, not via test-only exports
- `test/h2_prop_tests.erl` — PropEr property-based tests (encode/decode roundtrips)
- `test/h2_*_SUITE.erl` — Common Test: `h2_interop_SUITE` (h2spec over TLS + h2c
  + strict), `h2_compliance_SUITE`, `h2_grpc_interop_SUITE` /
  `h2_grpc_client_interop_SUITE`, `h2_robustness_SUITE`
- Raw-socket abuse/regression tests (e.g. `h2_made_you_reset_tests`,
  `h2_goaway_cancel_tests`, `h2_conn_window_tests`) build a minimal peer on
  `gen_tcp` + `h2_frame`/`h2_hpack` and assert exact wire behaviour
