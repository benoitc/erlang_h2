# Agent rules for erlang_h2

This is an HTTP/2 protocol library. Any agent (Claude, OpenCode, Cursor, Codex,
or other) working here follows the rules below.

## Protocol change review

A change to protocol code is not done when it compiles and the happy path works.
Before calling a change done, opening a PR, or releasing, run these three checks
and state their result in the PR or hand-off. This applies to edits to frame
encode/decode, the connection/stream state machine, flow control, settings, and
header compression.

1. **Compliance.** Run the project's conformance and unit suites and show they
   pass: `rebar3 eunit`, `rebar3 ct` (includes `h2spec` generic/hpack/strict and
   the interop suites), `rebar3 xref`, `rebar3 dialyzer`. Cite the spec section
   (e.g. `RFC 9113 §6.9.2`) for each rule the code enforces, and add a test for
   both the accept and the reject path. New behaviour is additive and opt-in;
   existing suites stay green with zero edits. To prove a new test is real, run it
   against a baseline from a `git worktree` at the merge base (not `git stash`),
   failing before the fix and passing after.

2. **Latest related specification.** Confirm the governing document is current
   before trusting it: an RFC may be obsoleted (HTTP/2: RFC 7540 → **RFC 9113**),
   an Internet-Draft revs often (`draft-ietf-...-NN`) and wire values/rules can
   change between revisions. Check via the IETF datatracker, read the actual
   section rather than recalling it, and note the version and date you checked.

3. **Safety.** The server is reachable by untrusted peers. Check the change
   against the known HTTP/2 abuse classes — Rapid Reset (CVE-2023-44487),
   MadeYouReset (CVE-2025-8671), HPACK decompression bomb, CONTINUATION flood
   (CVE-2024-27316), SETTINGS/PING floods, flow-control stalls, window overflow —
   and keep every per-peer resource bounded (concurrent streams, buffered bytes
   per stream and per connection, header-block size before decode, retained
   closed streams, pending settings). On a real vulnerability fix: add a
   raw-socket regression test, a `Security` CHANGELOG entry, and a published
   GitHub Security Advisory referencing the CVE.

The full checklist, with the same content for every repo, is the
`protocol-change-review` skill under `.claude/skills/`.

## Conventions

- Read the files you change before editing them; prefer small, exact edits.
- CHANGELOG entries and release notes: short, plain English, what was wrong or
  new and what it means for the user; no code snippets or internal detail.
- PR descriptions: state the intent and the fix in a few lines and any breaking
  changes; do not walk the diff file by file. No test-plan section.
