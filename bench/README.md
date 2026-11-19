# Benchmarks and diagnostics

This directory holds the scripts used to measure `h2` and to investigate
performance problems. Use it when you change a hot path and want numbers
before and after. Nothing here is built or run by the test suite.

You need `h2load` (from nghttp2) for the throughput runs. Build the library
first with `rebar3 compile`.

## Throughput

```bash
bench/start_h2.sh 8081          # h2c server, "Hello, World!" handler
bench/run.sh 8081 200000 16 16  # port, requests, clients, streams per client
```

`bench/one.sh <which> <port> <n> <c> <m>` starts a fresh server, runs one
load and stops it; `<which>` selects `start_<which>.sh`.

| File | What it serves or does |
| --- | --- |
| `bench_h2.erl` | Server using `h2:send_response/4` then `h2:send_data/4`. |
| `bench_h2_respond.erl` | Same response through `h2:respond/5`: one call, one write. |
| `bench_h2_204.erl` | A 204, to isolate the cost of the second call and write. |
| `bench_cowboy.erl`, `bench_cowboy_h.erl`, `start_cowboy.sh` | The same handler on cowboy, for comparison. |
| `run.sh`, `one.sh`, `lib.sh` | `h2load` wrappers and port helpers. |

## Microbenchmarks and diagnostics

| File | What it measures |
| --- | --- |
| `decbench.erl` | HPACK decode: a typical header set with a warm table, and a lookup of the oldest entry in a deep table. |
| `prof.erl` | Runs requests over one raw connection under `fprof` and prints the functions with the most own time. |
| `leak.erl` | Sequential requests on one client connection, to check completed streams stop counting as active. |
| `diag.erl` | Opens connections at the same moment, each sending a burst of requests, and reports what came back per connection. |
| `diag2.erl`, `diag3.erl` | A raw client that keeps a fixed number of streams in flight, like `h2load`. |

## Notes

- Compare against a baseline built from a `git worktree` at the commit you
  started from, not from `git stash`.
- `lib.sh`, `one.sh` and `start_cowboy.sh` contain absolute paths from the
  machine they were written on. Set `BENCH_ROOT`, or edit the paths, before
  you run them elsewhere.
- Numbers depend on the machine. Report ratios, not absolutes.
