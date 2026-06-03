#!/usr/bin/env bash
# Usage: run.sh <port> <n> <c> <m> <t>
PORT="$1"; N="$2"; C="$3"; M="$4"; T="${5:-4}"
h2load -n "$N" -c "$C" -m "$M" -t "$T" "http://127.0.0.1:${PORT}/" 2>&1 \
  | grep -E 'finished in|requests:|status codes:|req/s' \
  | sed 's/^/  /'
