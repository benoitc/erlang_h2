#!/usr/bin/env bash
# Fresh server, single load run. Usage: one.sh <which> <port> <n> <c> <m> <t>
source /Users/benoitc/Projects/erlang_h2/bench/lib.sh
which="$1"; port="$2"; n="$3"; c="$4"; m="$5"; t="${6:-4}"
log="/tmp/${which}_one.log"
stop_server "$port" >/dev/null 2>&1
: > "$log"
bash "$ROOT/bench/start_${which}.sh" "$port" > "$log" 2>&1 &
wait_port_up "$port" >/dev/null 2>&1; sleep 0.5
printf "%-6s c=%-3s m=%-3s n=%-7s: " "$which" "$c" "$m" "$n"
load "$port" "$n" "$c" "$m" "$t"
cr=$(grep -c 'handler crash' "$log" 2>/dev/null)
[ "$cr" -gt 0 ] && echo "        server crashes: $cr"
stop_server "$port" >/dev/null 2>&1
