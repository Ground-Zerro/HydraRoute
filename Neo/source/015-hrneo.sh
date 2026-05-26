#!/bin/sh

pidfile="/var/run/hrneo.pid"
[ -f "$pidfile" ] || exit 0

pid=$(cat "$pidfile" 2>/dev/null)
[ -n "$pid" ] && [ -d "/proc/$pid" ] && kill -USR1 "$pid"

exit 0