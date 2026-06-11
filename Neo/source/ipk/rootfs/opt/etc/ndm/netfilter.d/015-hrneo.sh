#!/bin/sh

#[ "$type" = "ip6tables" -o "$type" = "iptables" ] || exit 0
#[ "$table" = "mangle" ] || exit 0

pidfile="/var/run/hrneo.pid"
[ -f "$pidfile" ] || exit 0

pid=$(cat "$pidfile" 2>/dev/null)
[ -n "$pid" ] && [ -d "/proc/$pid" ] && kill -USR1 "$pid"

exit 0
