#!/usr/bin/env bash
# Start cowboy h2c server on $1 (default 8082)
set -e
PORT="${1:-8082}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CB=/Users/benoitc/Projects/hornbeam/_build/default/lib
exec erl -noshell \
  -pa "$ROOT/bench" \
  -pa "$CB/cowboy/ebin" -pa "$CB/cowlib/ebin" -pa "$CB/ranch/ebin" \
  +S "${SCHED:-14}" \
  -run bench_cowboy start "$PORT"
