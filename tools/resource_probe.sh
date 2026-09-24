#!/usr/bin/env bash
# resource_probe.sh — sample RSS / fd / threads / idle-CPU of an ssr_client.
#
# Two modes:
#
#   tools/resource_probe.sh <pid>
#       One-shot sample (the T6 soak loop calls this every 30s):
#       prints "rss_kb=<KB> fd=<N> threads=<N>". Exit 1 if unreadable.
#
#   tools/resource_probe.sh --idle [-c <config>] [-w <warmup_s>] [-m <measure_s>]
#       R1 baseline: start the client, let it sit idle, then measure and
#       check GOALS R1 targets:
#           idle RSS <= 20MB, threads <= nproc+4, idle CPU = 0%
#       Default config: ./config.json when present, else a generated local one
#       (idle measurement makes no connections either way). Exits non-zero
#       when a target is missed.
#
# Env: SSR_CLIENT overrides the client binary (release preferred by callers).
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"

sample_once() { # sample_once <pid> -> "rss_kb=.. fd=.. threads=.."; rc=1 if gone
    local pid=$1 rss fd thr
    [ -r "/proc/$pid/status" ] || return 1
    rss=$(awk '/^VmRSS:/{print $2}' "/proc/$pid/status") || return 1
    [ -n "$rss" ] || return 1
    fd=$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    thr=$(ps -o nlwp= -p "$pid" 2>/dev/null | tr -d ' ')
    echo "rss_kb=$rss fd=$fd threads=$thr"
}

cpu_pct() { # cpu_pct <pid> <seconds> -> percent of one core, 2 decimals
    local pid=$1 secs=$2 hz t0 t1
    hz=$(getconf CLK_TCK)
    t0=$(awk '{print $14+$15}' "/proc/$pid/stat")
    sleep "$secs"
    [ -r "/proc/$pid/stat" ] || { echo "-1"; return; }
    t1=$(awk '{print $14+$15}' "/proc/$pid/stat")
    awk -v d=$((t1 - t0)) -v hz="$hz" -v s="$secs" \
        'BEGIN{printf "%.2f", d * 100 / hz / s}'
}

if [ "$#" -eq 1 ] && [ "${1:-}" != "--idle" ]; then
    sample_once "$1"
    exit $?
fi

# ---- --idle mode -----------------------------------------------------------
CONFIG=""
WARMUP=5
MEASURE=5
while [ "$#" -gt 0 ]; do
    case "$1" in
        -c) CONFIG=$2; shift 2 ;;
        -w) WARMUP=$2; shift 2 ;;
        -m) MEASURE=$2; shift 2 ;;
        --idle) shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[ -n "$CONFIG" ] || { [ -r "$REPO/config.json" ] && CONFIG="$REPO/config.json"; }
if [ -z "$CONFIG" ]; then
    CONFIG=$(mktemp /tmp/probe_idle.XXXXXX.json)
    cat > "$CONFIG" <<EOF
{
  "server": "127.0.0.1",
  "server_port": 18999,
  "local_address": "127.0.0.1",
  "listen_port": 18998,
  "password": "probe_idle",
  "method": "aes-256-cfb",
  "protocol": "origin",
  "protocol_param": "",
  "obfs": "plain",
  "obfs_param": "",
  "timeout": 60,
  "udp": false,
  "idle_timeout": 300
}
EOF
fi

CLIENT="${SSR_CLIENT:-}"
if [ -z "$CLIENT" ]; then
    if [ -x "$REPO/target/release/ssr_client" ]; then
        CLIENT="$REPO/target/release/ssr_client"
    else
        CLIENT="$REPO/target/debug/ssr_client"
    fi
fi
[ -x "$CLIENT" ] || { echo "client binary not found: $CLIENT" >&2; exit 2; }

LOG=$(mktemp /tmp/probe_idle.XXXXXX.log)
"$CLIENT" -c "$CONFIG" > "$LOG" 2>&1 &
PID=$!
cleanup() { kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; }
trap cleanup EXIT

sleep 1
if ! kill -0 "$PID" 2>/dev/null; then
    echo "client failed to start:" >&2
    tail -5 "$LOG" >&2
    exit 2
fi
sleep "$WARMUP"

line=$(sample_once "$PID") || { echo "client died during warmup" >&2; exit 2; }
eval "${line// /;}" 2>/dev/null || true
rss_kb=${line#*rss_kb=}; rss_kb=${rss_kb%% *}
rest=${line#*fd=}; fd=${rest%% *}; thr=${rest#*threads=}
cpu=$(cpu_pct "$PID" "$MEASURE")

nproc_n=$(nproc)
thr_max=$((nproc_n + 4))
rss_ok=FAIL; [ "$rss_kb" -le 20480 ] && rss_ok=PASS
thr_ok=FAIL; [ "$thr" -le "$thr_max" ] && thr_ok=PASS
cpu_ok=FAIL; awk -v c="$cpu" 'BEGIN{exit !(c >= 0 && c <= 0.5)}' && cpu_ok=PASS

echo "config=$CONFIG client=$CLIENT"
echo "idle_rss_kb=$rss_kb   (<=20480)      $rss_ok"
echo "threads=$thr   (<=nproc+4=$thr_max) $thr_ok"
echo "idle_cpu_pct=$cpu   (<=0.5)      $cpu_ok"
echo "fd=$fd   (baseline for comparison)"

[ "$rss_ok" = PASS ] && [ "$thr_ok" = PASS ] && [ "$cpu_ok" = PASS ]
