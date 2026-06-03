#!/usr/bin/env bash
# Shared bench helpers. Source this.
ROOT="${BENCH_ROOT:-/Users/benoitc/Projects/erlang_h2}"

port_free() { ! lsof -ti tcp:"$1" >/dev/null 2>&1; }

wait_port_free() {
  local p="$1" i=0
  while ! port_free "$p"; do
    lsof -ti tcp:"$p" | xargs kill -9 2>/dev/null
    sleep 0.3; i=$((i+1)); [ "$i" -gt 40 ] && { echo "port $p stuck" >&2; return 1; }
  done
}

wait_port_up() {
  local p="$1" i=0
  while ! nc -z 127.0.0.1 "$p" >/dev/null 2>&1; do
    sleep 0.2; i=$((i+1)); [ "$i" -gt 50 ] && { echo "port $p never came up" >&2; return 1; }
  done
}

start_server() { # which(h2|cowboy) port logfile
  local which="$1" port="$2" log="$3"
  wait_port_free "$port" || return 1
  bash "$ROOT/bench/start_${which}.sh" "$port" > "$log" 2>&1 &
  wait_port_up "$port" || return 1
  sleep 0.5
}

stop_server() { # port
  lsof -ti tcp:"$1" | xargs kill -9 2>/dev/null
  wait_port_free "$1"
}

# h2load run -> prints "REQS req/s | ok=N err=N | p50=.. p99=.." (no kill; let it finish)
load() { # port n c m t
  local port="$1" n="$2" c="$3" m="$4" t="${5:-4}"
  h2load -n "$n" -c "$c" -m "$m" -t "$t" "http://127.0.0.1:${port}/" 2>&1 | awk '
    /finished in/ { for(i=1;i<=NF;i++) if($i=="req/s,"){gsub(/,/,"",$(i-1)); rps=$(i-1)} }
    /^requests:/  { for(i=1;i<=NF;i++){ if($(i+1)=="succeeded,")ok=$i; if($(i+1)=="errored,")er=$i } }
    /^\s*time for request:/ {}
    END { printf "%10s req/s | ok=%-7s err=%-7s\n", rps, ok, er }'
}
