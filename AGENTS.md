# Agents

Instructions for AI coding agents working on this project. The full text
lives in `docs/`, shared with human contributors; this file is the entry
point tools load.

## Project

Pure Erlang HTTP/2 implementation (RFC 9113) with zero external runtime
dependencies: client, server, HPACK, flow control, GOAWAY, CONTINUATION
handling, gRPC-style bidirectional streaming, and Extended CONNECT with the
hooks WebTransport needs. Requires Erlang/OTP and rebar3.

## Read before you change anything

- [docs/agents.md](docs/agents.md): the rules for agents, pull requests and
  skills.
- [docs/architecture.md](docs/architecture.md): the connection process,
  where events go, the limits against a hostile peer, what is public.
- [docs/contributing.md](docs/contributing.md): how to write a test, where to
  change what, and the "If you want to..." guides.
- [docs/internals/connection.md](docs/internals/connection.md): required
  before editing `src/h2_connection.erl`.
- [docs/internals/wire.md](docs/internals/wire.md): the frame, HPACK,
  settings and capsule codecs.

## Required checks

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
summerwind/h2spec/h2spec`, or the Linux release tarball); the gRPC and curl
interop suites skip cleanly when their tool is absent.

## Protocol change review

A change to protocol code is not done when it compiles and the happy path
works. Before calling a change done, opening a pull request, or releasing, run
the three checks in the
[protocol-change-review](.agents/skills/protocol-change-review/SKILL.md)
skill: compliance, the latest related specification, safety.

## No breaking changes

Do not rename or move a module, change an exported function, or change the
shape of an event without the maintainer's agreement. Other projects call
`h2`, `h2_capsule`, `h2_varint` and `h2_error` directly.

## Skills

Task guides for agents live in `.agents/skills/<name>/SKILL.md`; read the one
that matches the task before starting. `.claude/skills` links to the same
directories, so there is one copy.

- [protocol-change-review](.agents/skills/protocol-change-review/SKILL.md): check
  a change or pull request for compliance, the latest related spec, and safety.
