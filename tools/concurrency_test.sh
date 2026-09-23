#!/usr/bin/env bash
# concurrency_test.sh — GOALS P4: throughput scaling curve at
# 1 / 8 / 64 / 100 concurrent streams through the local ssr-server.
#
# Per fixed-DURATION window each concurrency level runs N persistent
# curl loops against the local HTTP origin; total downloaded bytes /
# wall time = aggregate throughput. Client CPU/RSS/fd sampled around
# each window to spot lock-contention saturation (throughput plateau
# while CPU sits well below the core budget = lock hotspot; plateau
# with all 4 cores busy = compute-bound, no lock issue).
#
# Env overrides: HTTP_PORT SRV_PORT CL_PORT DURATION ORIGIN_MIB LEVELS
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
HTTP_PORT="${HTTP_PORT:-18095}"
SRV_PORT="${SRV_PORT:-18995}"
CL_PORT="${CL_PORT:-11085}"
DURATION="${DURATION:-15}"
ORIGIN_MIB="${ORIGIN_MIB:-64}"
LEVELS="${LEVELS:-1 8 64 100}"
METHOD="${METHOD:-aes-256-cfb}"

WORK="$(mktemp -d /tmp/p4.XXXXXX)"
WWW="$WORK/www"
mkdir -p "$WWW"
cp -a www/* "$WWW"/ 2>/dev/null || true
if [ ! -f "$WWW/bench64.bin" ] || [ "$(stat -c %s "$WWW/bench64.bin" 2>/dev/null)" -ne $((ORIGIN_MIB * 1024 * 1024)) ]; then
    dd if=/dev/urandom of="$WWW/bench64.bin" bs=1M count="$ORIGIN_MIB" status=none
fi

cleanup() {
    { pkill -9 -P "$WORK" 2>/dev/null
      pkill -9 -f "http.server $HTTP_PORT" 2>/dev/null
      pkill -9 -x ssr-server 2>/dev/null
      pkill -9 -x ssr_client 2>/dev/null
      pkill -9 -f "socks_loops" 2>/dev/null; } 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

cat > "$WORK/srv.json" <<EOF
{ "server": "127.0.0.1", "server_port": $SRV_PORT, "local_address": "127.0.0.1",
  "local_port": $((CL_PORT + 50)), "password": "test-password", "method": "$METHOD",
  "protocol": "auth_aes128_sha1", "obfs": "tls1.2_ticket_auth", "timeout": 60 }
EOF
cat > "$WORK/cli.json" <<EOF
{ "server": "127.0.0.1", "server_port": $SRV_PORT, "local_address": "127.0.0.1",
  "listen_port": $CL_PORT, "local_port": $CL_PORT,
  "password": "test-password", "method": "$METHOD",
  "protocol": "auth_aes128_sha1", "obfs": "tls1.2_ticket_auth",
  "timeout": 60, "udp": false }
EOF

(cd "$WWW" && python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
echo $! > "$WORK/http.pid"
/opt/ssr/ssr-server -c "$WORK/srv.json" >"$WORK/srv.log" 2>&1 &
echo $! > "$WORK/srv.pid"
sleep 1
HTTP_PID=$(cat "$WORK/http.pid")
SRV_PID=$(cat "$WORK/srv.pid")
"$ROOT/target/release/ssr_client" -c "$WORK/cli.json" >"$WORK/cli.log" 2>&1 &
echo $! > "$WORK/cli.pid"
sleep 1
CLI_PID=$(cat "$WORK/cli.pid")
kill -0 "$CLI_PID" 2>/dev/null || { echo "client failed to start"; tail -3 "$WORK/cli.log"; exit 1; }

# N concurrent curl loops for DURATION seconds; sum size_download.
run_level() {
    local n=$1
    local deadline=$((SECONDS + DURATION))
    local bytesf="$WORK/bytes.$n"
    : > "$bytesf"
    for _i in $(seq 1 "$n"); do
        (
            local_total=0
            while [ "$SECONDS" -lt "$deadline" ]; do
                sz=$(curl -s -o /dev/null --max-time $((DURATION + 5)) \
                    --socks5-hostname "127.0.0.1:$CL_PORT" \
                    -w '%{size_download}' \
                    "http://127.0.0.1:$HTTP_PORT/bench64.bin" 2>/dev/null || echo 0)
                local_total=$((local_total + ${sz:-0}))
            done
            echo "$local_total" >> "$bytesf"
        ) &
    done
    wait
    awk '{s+=$1} END{printf "%.0f", s}' "$bytesf"
}

FD0=$(find /proc/"$CLI_PID"/fd -mindepth 1 2>/dev/null | wc -l)
RSS0=$(awk '/VmRSS/{print $2}' /proc/"$CLI_PID"/status)
t0=$(date +%s.%N)
c0=$(awk '{print $14+$15}' /proc/"$CLI_PID"/stat)

cpu_of() {  # percent over the window given pid + two stat snapshots
    awk -v a="$2" -v b="$3" -v h="$4" -v w="$5" 'BEGIN{ if (w>0) printf "%.0f", (b-a)/h*100/w; else print 0 }'
}
printf '| level | MiB/s | client CPU %% | server CPU %% | origin CPU %% | fd | RSS MiB |\n'
printf '|---|---:|---:|---:|---:|---:|---:|\n'
for n in $LEVELS; do
    hz=$(getconf CLK_TCK)
    w0=$(awk '{print $14+$15}' /proc/"$CLI_PID"/stat)
    v0=$(awk '{print $14+$15}' /proc/"$SRV_PID"/stat 2>/dev/null || echo 0)
    p0=$(awk '{print $14+$15}' /proc/"$HTTP_PID"/stat 2>/dev/null || echo 0)
    wall0=$(date +%s.%N)
    total=$(run_level "$n")
    wall1=$(date +%s.%N)
    w1=$(awk '{print $14+$15}' /proc/"$CLI_PID"/stat)
    v1=$(awk '{print $14+$15}' /proc/"$SRV_PID"/stat 2>/dev/null || echo 0)
    p1=$(awk '{print $14+$15}' /proc/"$HTTP_PID"/stat 2>/dev/null || echo 0)
    wall=$(awk -v a="$wall0" -v b="$wall1" 'BEGIN{print b-a}')
    cpu=$(cpu_of x "$w0" "$w1" "$hz" "$wall")
    srvcpu=$(cpu_of x "$v0" "$v1" "$hz" "$wall")
    httpcpu=$(cpu_of x "$p0" "$p1" "$hz" "$wall")
    mibs=$(awk -v t="$total" -v w="$wall" 'BEGIN{printf "%.1f", t/w/1048576}')
    fd=$(find /proc/"$CLI_PID"/fd -mindepth 1 2>/dev/null | wc -l)
    rss=$(awk '/VmRSS/{printf "%.1f", $2/1024}' /proc/"$CLI_PID"/status)
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$n" "$mibs" "$cpu" "$srvcpu" "$httpcpu" "$fd" "$rss"
    sleep 3   # let per-connection tasks drain between levels
done

c1=$(awk '{print $14+$15}' /proc/"$CLI_PID"/stat)
FD1=$(find /proc/"$CLI_PID"/fd -mindepth 1 2>/dev/null | wc -l)
RSS1=$(awk '/VmRSS/{print $2}' /proc/"$CLI_PID"/status)
echo "SUMMARY fd0=$FD0 fd1=$FD1 rss0=$RSS0 rss1=$RSS1"
