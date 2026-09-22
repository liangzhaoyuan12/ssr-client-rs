#!/usr/bin/env bash
# fd_leak_test.sh — R2 fd leak gate (GOALS Phase R).
#
# Asserts, against the R1 baseline (fd=11 for an idle client):
#   1. TCP: 500 connect/transfer/close cycles through the SOCKS5 proxy,
#      then the client's fd count returns to baseline (0 leaks).
#   2. UDP: create 100 relay sessions (one app socket, 100 distinct target
#      ports -> 100 distinct SessionKeys), watch fd rise by ~100, then wait
#      for `udp_timeout` to expire and assert the session table drained and
#      fd fell back to baseline (udp_relay eviction works).
#
# Usage:   tools/fd_leak_test.sh
# Env:     TCP_CYCLES (default 500), UDP_SESSIONS (default 100),
#          UDP_TIMEOUT (client cfg, default 4s), SSR_SERVER, SSR_CLIENT.
# Exit 0 + "FD_LEAK_PASS" on success.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSR_SERVER="${SSR_SERVER:-/opt/ssr/ssr-server}"
CLIENT="${SSR_CLIENT:-$REPO/target/release/ssr_client}"
[ -x "$CLIENT" ] || CLIENT="$REPO/target/debug/ssr_client"
TCP_CYCLES="${TCP_CYCLES:-500}"
UDP_SESSIONS="${UDP_SESSIONS:-100}"
UDP_TIMEOUT="${UDP_TIMEOUT:-4}"
SRV_PORT=18911
SOCKS_PORT=19915
HTTP_PORT=18081
WORK="$(mktemp -d /tmp/ssr_fd_leak.XXXXXX)"
PASSWORD="fd_leak_test_pw"
PIDS=()

cleanup() {
    local rc=$?
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    [ "$rc" -eq 0 ] && rm -rf "$WORK" || echo "--- logs kept at $WORK ---"
    exit "$rc"
}
trap cleanup EXIT INT TERM
die() { echo "FD_LEAK_FAIL: $*" >&2; exit 1; }

fd_of() { find "/proc/$1/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l; }
wait_fd() { # wait_fd <pid> <target> <label> — retry up to 10s for fd==target
    local pid=$1 want=$2 label=$3 i got
    for i in $(seq 1 20); do
        got=$(fd_of "$pid")
        [ "$got" = "$want" ] && return 0
        sleep 0.5
    done
    die "$label: fd=$got, expected $want (baseline $want)"
}
wait_port() {
    local proto=$1 port=$2 label=$3 i flag
    [ "$proto" = udp ] && flag="-ulnt" || flag="-lnt"
    for i in $(seq 1 50); do
        ss "$flag" 2>/dev/null | grep -q ":$port " && return 0
        sleep 0.2
    done
    die "$label port $port did not come up"
}

[ -x "$SSR_SERVER" ] || die "ssr-server not found: $SSR_SERVER"
command -v curl >/dev/null || die "curl required"

# local HTTP origin (64KB blob)
python3 -c "open('$WORK/blob','wb').write(b'x'*65536)"
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK" \
    > "$WORK/http.log" 2>&1 &
PIDS+=($!)

cat > "$WORK/srv.json" <<EOF
{"server":"127.0.0.1","server_port":$SRV_PORT,"method":"aes-256-cfb",
 "protocol":"origin","protocol_param":"","obfs":"plain","obfs_param":"",
 "password":"$PASSWORD","timeout":60,"udp":true}
EOF
cat > "$WORK/cli.json" <<EOF
{"server":"127.0.0.1","server_port":$SRV_PORT,"method":"aes-256-cfb",
 "protocol":"origin","protocol_param":"","obfs":"plain","obfs_param":"",
 "password":"$PASSWORD","local_address":"127.0.0.1","listen_port":$SOCKS_PORT,
 "udp":true,"udp_timeout":$UDP_TIMEOUT}
EOF

"$SSR_SERVER" -c "$WORK/srv.json" > "$WORK/srv.log" 2>&1 & PIDS+=($!)
wait_port udp "$SRV_PORT" server
"$CLIENT" -c "$WORK/cli.json" > "$WORK/cli.log" 2>&1 & CLIENT_PID=$!
PIDS+=($CLIENT_PID)
wait_port tcp "$SOCKS_PORT" client-tcp
wait_port udp "$SOCKS_PORT" client-udp
sleep 1

# ---- baseline --------------------------------------------------------------
BASE=$(fd_of "$CLIENT_PID")
[ "$BASE" -ge 5 ] || die "baseline fd=$BASE looks wrong"
echo "baseline_fd=$BASE"

# ---- 1) TCP: 500 cycles, fd must return to baseline ------------------------
FAILS=0
for i in $(seq 1 "$TCP_CYCLES"); do
    curl -s -o /dev/null --max-time 10 \
        --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        "http://127.0.0.1:$HTTP_PORT/blob" || FAILS=$((FAILS + 1))
done
echo "tcp_cycles=$TCP_CYCLES failures=$FAILS"
[ "$FAILS" -eq 0 ] || die "TCP transfers failed: $FAILS/$TCP_CYCLES"
wait_fd "$CLIENT_PID" "$BASE" "after-TCP-500"
echo "after_tcp_fd=$(fd_of "$CLIENT_PID") (== baseline $BASE) PASS"

# ---- 2) UDP: 100 sessions, fd rises, then drains after udp_timeout ---------
UDP_OUT=$(SOCKS_PORT="$SOCKS_PORT" UDP_N="$UDP_SESSIONS" python3 - <<'PY'
import os, socket, struct, sys
port = int(os.environ["SOCKS_PORT"]); n = int(os.environ["UDP_N"])
t = socket.create_connection(("127.0.0.1", port), 5)
t.sendall(b"\x05\x01\x00")
assert t.recv(2) == b"\x05\x00", "method negotiation"
t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep = t.recv(32)
assert rep[0] == 5 and rep[1] == 0, f"associate rep {rep!r}"
relay_port = struct.unpack(">H", rep[-2:])[0]
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", 0))
for i in range(n):
    tgt = struct.pack(">H", 21001 + i)
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + tgt
    u.sendto(hdr + b"x" * 8, ("127.0.0.1", relay_port))
print(f"sent={n} relay_port={relay_port}")
u.close()
t.close()
PY
) || die "UDP burst script failed: $UDP_OUT"
echo "$UDP_OUT"

sleep 1.5   # let the relay spawn session tasks + bind sockets
PEAK=$(fd_of "$CLIENT_PID")
DELTA=$((PEAK - BASE))
echo "peak_fd=$PEAK (baseline $BASE, delta +$DELTA)"
# each session = 1 bound socket; require most of them visible (>=80%)
MIN_PEAK=$((BASE + UDP_SESSIONS * 8 / 10))
[ "$PEAK" -ge "$MIN_PEAK" ] || \
    die "peak fd=$PEAK < $MIN_PEAK — sessions were not created ($UDP_SESSIONS requested)"

EXPIRY=$((UDP_TIMEOUT + 6))
echo "waiting ${EXPIRY}s for udp_timeout=${UDP_TIMEOUT}s eviction..."
sleep "$EXPIRY"
wait_fd "$CLIENT_PID" "$BASE" "after-UDP-eviction"
echo "after_udp_fd=$(fd_of "$CLIENT_PID") (== baseline $BASE) PASS"

echo "FD_LEAK_PASS tcp=$TCP_CYCLES udp=$UDP_SESSIONS baseline=$BASE"
