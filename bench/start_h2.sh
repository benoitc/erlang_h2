#!/usr/bin/env bash
# Start erlang_h2 h2c server on $1 (default 8081)
set -e
PORT="${1:-8081}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec erl -noshell \
  -pa "$ROOT/bench" \
  -pa "$ROOT/_build/default/lib/h2/ebin" \
  +S "${SCHED:-14}" \
  -run bench_h2 start "$PORT"
