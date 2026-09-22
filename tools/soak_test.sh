#!/usr/bin/env bash
# soak_test.sh — T6 long-run stability (GOALS: 10 min sustained transfer,
# sample RSS/fd/threads every 30s, assert growth <= 10MB after warmup,
# fd returns to baseline, no panic).
#
# Traffic:
#   * TCP: curl of a 64KB local file through the SOCKS5 proxy every 2s
#   * UDP: tests/e2e/test_udp_e2e.py loop (fresh SOCKS/UDP session each run,
#          rotating echo port) every 30s — exercises session create/teardown,
#          which is what exposes fd leaks
#
# Usage:
#   tools/soak_test.sh                    # full 600s
#   SOAK_DURATION=90 WARMUP=30 SAMPLE_INTERVAL=15 tools/soak_test.sh   # smoke
#
# Env knobs: SOAK_DURATION, WARMUP, SAMPLE_INTERVAL, SSR_SERVER, SSR_CLIENT.
# Exit 0 + "SOAK_PASS" on success; exit 1 with failing assertion otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSR_SERVER="${SSR_SERVER:-/opt/ssr/ssr-server}"
DURATION="${SOAK_DURATION:-600}"
WARMUP="${WARMUP:-60}"
INTERVAL="${SAMPLE_INTERVAL:-30}"

SRV_PORT=18610
CLI_PORT=18961
HTTP_PORT=18611
PASSWORD="soak_password_1"
METHOD="aes-256-cfb"
PROTOCOL="auth_aes128_sha1"
OBFs="plain"

WORK="$(mktemp -d /tmp/ssr_soak.XXXXXX)"
PIDS=()
TCP_OK=0; TCP_FAIL=0; UDP_OK=0; UDP_FAIL=0
TCP_LOOP_PID=""; UDP_LOOP_PID=""; CLIENT_PID=""

cleanup() {
    local rc=$?
    [ -n "$TCP_LOOP_PID" ] && kill "$TCP_LOOP_PID" 2>/dev/null
    [ -n "$UDP_LOOP_PID" ] && kill "$UDP_LOOP_PID" 2>/dev/null
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    wait 2>/dev/null
    if [ "$rc" -ne 0 ]; then
        echo "--- soak failed; logs kept at $WORK ---"
        for f in "$WORK"/*.log; do echo "== $f =="; tail -15 "$f"; done
    else
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

die() { echo "FAIL: $*" >&2; exit 1; }

[ -x "$SSR_SERVER" ] || die "ssr-server not found: $SSR_SERVER"
CLIENT="${SSR_CLIENT:-}"
if [ -z "$CLIENT" ]; then
    if [ -x "$REPO/target/release/ssr_client" ]; then
        CLIENT="$REPO/target/release/ssr_client"
    else
        CLIENT="$REPO/target/debug/ssr_client"
        [ -x "$CLIENT" ] || { (cd "$REPO" && cargo build --quiet) || die "cargo build"; }
    fi
fi

wait_port() { # wait_port <port> <label>
    local port=$1 label=$2 i
    for i in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&- || true
            return 0
        fi
        sleep 0.1
    done
    die "$label did not bind $port"
}

cfg() { # cfg <path> <extra-keys>
    cat > "$1" <<EOF
{
  "server": "127.0.0.1",
  "server_port": $SRV_PORT,
  "local_address": "127.0.0.1",
  "listen_port": $CLI_PORT,
  "password": "$PASSWORD",
  "method": "$METHOD",
  "protocol": "$PROTOCOL",
  "protocol_param": "",
  "obfs": "$OBFs",
  "obfs_param": "",
  "timeout": 60,
  "udp": true,
  "idle_timeout": 300
}
EOF
}

sample() { # sample <label> -> echoes one line, dies if client is gone
    local out
    out=$("$REPO/tools/resource_probe.sh" "$CLIENT_PID") || die "client process gone at $1"
    echo "[$1] $out"
}

echo "soak: duration=${DURATION}s warmup=${WARMUP}s interval=${INTERVAL}s work=$WORK"

# --- local HTTP target: 64KB file ------------------------------------------
mkdir -p "$WORK/www"
head -c 65536 /dev/urandom > "$WORK/www/blob.bin"
(cd "$WORK/www" && exec python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1) \
    > "$WORK/http.log" 2>&1 &
PIDS+=($!)
wait_port "$HTTP_PORT" "http target"

# --- ssr-server + client ----------------------------------------------------
cfg "$WORK/srv.json"
cfg "$WORK/cli.json"
"$SSR_SERVER" -c "$WORK/srv.json" > "$WORK/srv.log" 2>&1 &
PIDS+=($!)
wait_port "$SRV_PORT" "ssr-server"

"$CLIENT" -c "$WORK/cli.json" > "$WORK/cli.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")
wait_port "$CLI_PORT" "client"

# --- traffic loops ----------------------------------------------------------
# TCP: 2s cadence; each loop iteration bumps $TCP_OK/$TCP_FAIL via a shared
# counter file (subshell can't mutate parent vars).
(
    while :; do
        if curl -s -x "socks5h://127.0.0.1:$CLI_PORT" \
            "http://127.0.0.1:$HTTP_PORT/blob.bin" -o /dev/null --max-time 10
        then echo ok >> "$WORK/tcp.count"; else echo fail >> "$WORK/tcp.count"; fi
        sleep 2
    done
) &
TCP_LOOP_PID=$!

# UDP: rotate echo port per run so rebinding is clean between iterations.
(
    i=0
    while :; do
        eport=$((20600 + (i % 40)))
        if SOCKS_PORT="$CLI_PORT" ECHO_PORT="$eport" \
            timeout 15 python3 "$REPO/tests/e2e/test_udp_e2e.py" \
            > "$WORK/udp_last.log" 2>&1
        then echo ok >> "$WORK/udp.count"; else echo fail >> "$WORK/udp.count"; fi
        i=$((i + 1))
        sleep 30
    done
) &
UDP_LOOP_PID=$!

# --- warmup, then baseline + periodic sampling ------------------------------
sleep "$WARMUP"
BASE=$(sample baseline)
BASE_RSS=${BASE#*rss_kb=}; BASE_RSS=${BASE_RSS%% *}
BASE_REST=${BASE#*fd=}; BASE_FD=${BASE_REST%% *}
echo "baseline after ${WARMUP}s: rss_kb=$BASE_RSS fd=$BASE_FD"

MAX_RSS=$BASE_RSS
END=$((SECONDS + DURATION - WARMUP))
while [ "$SECONDS" -lt "$END" ]; do
    sleep "$INTERVAL"
    S=$(sample "t+$((SECONDS))s")
    R=${S#*rss_kb=}; R=${R%% *}
    [ "$R" -gt "$MAX_RSS" ] && MAX_RSS=$R
done

# --- drain: stop traffic, let connections close, final sample ---------------
kill "$TCP_LOOP_PID" "$UDP_LOOP_PID" 2>/dev/null
TCP_LOOP_PID=""; UDP_LOOP_PID=""
sleep 5
FINAL=$(sample final)
FINAL_RSS=${FINAL#*rss_kb=}; FINAL_RSS=${FINAL_RSS%% *}
FINAL_REST=${FINAL#*fd=}; FINAL_FD=${FINAL_REST%% *}

TCP_OK=$(wc -l < "$WORK/tcp.count" 2>/dev/null | tr -d ' ')
TCP_FAIL=$(grep -c '^fail$' "$WORK/tcp.count" 2>/dev/null || true)
UDP_OK=$(grep -c '^ok$' "$WORK/udp.count" 2>/dev/null || true)
UDP_FAIL=$(grep -c '^fail$' "$WORK/udp.count" 2>/dev/null || true)
TCP_FAIL=${TCP_FAIL:-0}; UDP_OK=${UDP_OK:-0}; UDP_FAIL=${UDP_FAIL:-0}
TCP_OK=$(grep -c '^ok$' "$WORK/tcp.count" 2>/dev/null || true); TCP_OK=${TCP_OK:-0}

GROWTH=$((FINAL_RSS - BASE_RSS))
PANIC=$(grep -ci 'panic' "$WORK/cli.log" 2>/dev/null || true); PANIC=${PANIC:-0}

echo "tcp: $TCP_OK ok / $TCP_FAIL fail   udp: $UDP_OK ok / $UDP_FAIL fail"
echo "rss: baseline=${BASE_RSS}KB final=${FINAL_RSS}KB growth=${GROWTH}KB max_seen=${MAX_RSS}KB"
echo "fd:  baseline=$BASE_FD final=$FINAL_FD"
echo "client panics: $PANIC"

FAILS=0
[ "$TCP_FAIL" -eq 0 ] && [ "$TCP_OK" -gt 0 ] || { echo "ASSERT: tcp traffic (ok=$TCP_OK fail=$TCP_FAIL)"; FAILS=1; }
[ "$UDP_FAIL" -eq 0 ] && [ "$UDP_OK" -gt 0 ] || { echo "ASSERT: udp traffic (ok=$UDP_OK fail=$UDP_FAIL)"; FAILS=1; }
[ "$GROWTH" -le 10240 ] || { echo "ASSERT: RSS growth ${GROWTH}KB > 10MB"; FAILS=1; }
[ "$FINAL_FD" -le "$BASE_FD" ] || { echo "ASSERT: fd did not return to baseline ($FINAL_FD > $BASE_FD)"; FAILS=1; }
[ "$PANIC" -eq 0 ] || { echo "ASSERT: client log contains panic"; FAILS=1; }

if [ "$FAILS" -eq 0 ]; then
    echo "SOAK_PASS"
else
    exit 1
fi
