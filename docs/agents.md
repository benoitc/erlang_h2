# Instructions for coding agents

This page holds the rules that apply to an AI coding agent working on `h2`.
The repository root `AGENTS.md` points here. Everything a human contributor
follows applies to you too, so read these first:

- [Architecture](architecture.md): how the library is built and why.
- [Contributing](contributing.md): the checks, the test rules, where to
  change what.
- [Inside h2_connection](internals/connection.md) before you edit
  `src/h2_connection.erl`.

## Rules

- Read the files you are about to change before you edit them.
- Run every command under "Checks to run before every commit" in
  [Contributing](contributing.md) and report the real result. If a suite
  fails, say so and show the output.
- A change to protocol code is not done until you have run the three checks
  in the
  [protocol-change-review](https://github.com/benoitc/erlang_h2/blob/main/.agents/skills/protocol-change-review/SKILL.md)
  skill: compliance, the latest related specification, safety.
- Prove a new test against a `git worktree` at the merge base, not with
  `git stash`.
- Test private functions inside their module under `-ifdef(TEST)`. Do not add
  an export for a test.
- New behaviour is additive and off by default. Existing tests pass without
  edits. If a test encodes behaviour the RFC forbids, follow the RFC, change
  the test and flag it.
- Check symbol names against the current source before you cite them. Do not
  quote line numbers in documentation.
- Do not rename or move a module, change an exported function, or change the
  shape of an event without the maintainer's agreement.

## Pull requests

- One issue, one pull request, with its docs and CHANGELOG entry.
- The description holds the intent, the solution in a few lines, and any
  breaking change. No file-by-file walk, no test plan, no verification
  section.
- CHANGELOG entries and release notes are short, plain English, with no code
  and no internal names.

## Skills

Task guides live in `.agents/skills/<name>/SKILL.md`. `.claude/skills` links
to the same directories, so there is one copy.

- [protocol-change-review](https://github.com/benoitc/erlang_h2/blob/main/.agents/skills/protocol-change-review/SKILL.md):
  check a change or pull request for compliance, the latest related
  specification, and safety.
