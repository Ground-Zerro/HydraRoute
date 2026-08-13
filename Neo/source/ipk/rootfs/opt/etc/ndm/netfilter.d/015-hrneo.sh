#!/bin/sh

PIDFILE="/var/run/hrneo.pid"
CAPFILE="/var/run/hrneo.netfilter-sigusr2"

[ -f "$PIDFILE" ] || exit 0

pid=$(cat "$PIDFILE" 2>/dev/null)
[ -n "$pid" ] || exit 0
[ -d "/proc/$pid" ] || exit 0

signal=USR1
if [ -r "$CAPFILE" ]; then
    cap_pid=
    IFS= read -r cap_pid < "$CAPFILE"
    case "$cap_pid" in
        ''|*[!0-9]*) cap_pid= ;;
    esac
    [ "$cap_pid" = "$pid" ] && signal=USR2
fi

kill -"$signal" "$pid"

exit 0
