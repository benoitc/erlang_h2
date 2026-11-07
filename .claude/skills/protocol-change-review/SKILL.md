---
name: protocol-change-review
description: "Use when changing, reviewing, or releasing code that implements a wire/network protocol — HTTP/1, HTTP/2, HTTP/3, QUIC, WebTransport, WebSocket, gRPC, HPACK/QPACK, TLS record handling, or any frame/packet parser and state machine (repos such as erlang_h2, erlang_quic, hackney, gunicorn). Runs three checks before the change is called done: (1) compliance against the governing spec and the project's conformance suites, (2) the latest related specification or draft, (3) safety against known DoS/abuse classes. Trigger on edits to frame/packet encode-decode, connection/stream state machines, flow control, settings, header compression, and before any protocol-library release or PR."
---

# Protocol change review

A change to a protocol implementation is not done when the code compiles and the
happy path works. A wire protocol has three further obligations: it must match
the spec, it must match the *current* spec, and it must survive a hostile peer.
Run all three before calling the change done, opening the PR, or releasing.

Apply this to any frame/packet parser, connection or stream state machine, flow
control, settings negotiation, or header-compression code. When in doubt whether
it applies, it applies.

## 1. Compliance

Confirm the change still conforms, and that new behaviour is backed by a test.

- Find and run the project's conformance and interop suites, don't assume names.
  Search the repo first (`test/`, `rebar.config`, `Makefile`, CI workflows under
  `.github/`). For HTTP/2 that usually means `h2spec` (generic + hpack + strict),
  the unit suite, and any interop suite; for QUIC/HTTP3, the interop runner and
  the RFC-vector tests; for gRPC, the interop client/server.
- Run them against the change, and — when a reviewer needs proof a test is real —
  against a clean baseline from a `git worktree` at the merge base (not `git
  stash`), so a new test is shown failing before the fix and passing after.
- Every spec rule the code enforces should cite its section (e.g. `RFC 9113
  §6.9.2`). When you add or change enforcement, add a test that exercises both
  the accept and the reject path.
- Keep changes additive and opt-in where the project expects backward
  compatibility: existing conformance + unit suites stay green with zero edits.

## 2. Latest related specification

The spec the code cites may be superseded or revised. Check before trusting it.

- Identify the governing document for the touched behaviour and find its current
  version. An RFC may be obsoleted (HTTP/2: RFC 7540 → **RFC 9113**; HTTP/1:
  RFC 7230-series → **RFC 9110/9112**); an Internet-Draft revs often
  (`draft-ietf-...-NN`) and the newest `-NN` can change wire values or rules.
- Use web search / the IETF datatracker to confirm you have the latest, and read
  the specific section, don't answer from memory. Note the exact version and date
  you checked in the PR or commit so the next person knows the basis.
- When implementing an extension (WebTransport, Extended CONNECT, gRPC, Alt-Svc),
  verify the setting ids, frame types, and error codes against the current draft;
  these are exactly the values that drift between revisions.
- If the latest spec disagrees with the code, treat the gap as part of the change
  (fix it, or call it out explicitly as deliberately out of scope).

## 3. Safety

A protocol endpoint is reachable by untrusted peers. Review the change against
the known abuse classes for this protocol, and bound every per-peer resource.

- Walk the relevant DoS/abuse classes and check the change neither introduces nor
  reopens one. For HTTP/2: Rapid Reset (client RST flood, CVE-2023-44487),
  **MadeYouReset** (server-sent reset flood that frees concurrency slots,
  CVE-2025-8671), HPACK decompression bomb, CONTINUATION flood (CVE-2024-27316),
  SETTINGS/PING floods, zero-length-DATA/empty-frame floods, flow-control stalls,
  and window-overflow. For QUIC: amplification, stateless-reset and migration
  abuse, stream/flow-control exhaustion. The fix pattern is usually: count the
  abusive event per connection/second and tear down with the protocol's "calm"
  signal (HTTP/2 `GOAWAY(ENHANCE_YOUR_CALM)`) past a cap.
- Every per-peer structure needs a bound: concurrent streams, buffered bytes per
  stream and per connection, header-block size before decode, retained closed
  streams, pending settings, unacked data. A peer must not be able to grow any of
  them without limit.
- When the change fixes a real vulnerability: add a regression test that drives
  the attack over a raw socket and asserts the bound holds, write a CHANGELOG
  entry under a `Security` heading, and publish a GitHub Security Advisory
  (`gh api -X POST repos/<owner>/<repo>/security-advisories ...`, then `PATCH ...
  state=published`) referencing the CVE — GitHub as CNA can also assign one.
- Do not weaken a limit to make a legitimate client pass; instead exclude the
  legitimate case precisely (e.g. pre-admission `REFUSED_STREAM` and
  application-initiated cancels are not peer abuse and must not count).

## Output

State the result of each of the three checks in the PR/MR description or the
hand-off: which suites ran and passed, which spec version was checked, and which
abuse classes were considered. If one check was skipped, say so and why.
