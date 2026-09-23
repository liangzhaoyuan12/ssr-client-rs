#!/usr/bin/env bash
# bench_vs_c.sh — GOALS P2: end-to-end throughput + CPU vs the C client.
#
# Same machine, same server config, same 64 MiB transfer:
#   our Rust client  vs  /opt/ssr/ssr-client
# Targets (GOALS P2):
#   throughput >= 90% of C,  CPU <= 1.5x of C
#
# Method: local ssr-server + local HTTP source; 3 curl downloads of a 64 MiB
# random file through each client's SOCKS5 port; per-run wall time from
# curl's time_total, client CPU from /proc/PID/stat deltas (utime+stime).
# Median of 3 runs per client.  Results append to BENCH.md.
#
# Env overrides: SSR_SERVER C_CLIENT RUST_CLIENT METHOD PROTOCOL OBFS
#                RUNS PAYLOAD_MIB

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSR_SERVER="${SSR_SERVER:-/opt/ssr/ssr-server}"
C_CLIENT="${C_CLIENT:-/opt/ssr/ssr-client}"
RUST_CLIENT="${RUST_CLIENT:-$REPO/target/release/ssr_client}"
METHOD="${METHOD:-aes-256-cfb}"
PROTOCOL="${PROTOCOL:-auth_aes128_sha1}"
OBFS="${OBFS:-tls1.2_ticket_auth}"
RUNS="${RUNS:-3}"
PAYLOAD_MIB="${PAYLOAD_MIB:-64}"
PASSWORD="test-password"
SRV_PORT=18990
C_PORT=11081
R_PORT=11082
HTTP_PORT=18091
WORK=/tmp/ssr_p2

die() { echo "ERROR: $*" >&2; exit 1; }

[ -x "$SSR_SERVER" ] || die "ssr-server missing: $SSR_SERVER"
[ -x "$C_CLIENT" ]   || die "C client missing: $C_CLIENT"
[ -x "$RUST_CLIENT" ] || die "rust client missing: $RUST_CLIENT (cargo build --release)"
command -v curl >/dev/null || die "curl missing"

cleanup() {
    jobs -p | xargs -r kill -9 2>/dev/null
    pkill -9 -f "http.server $HTTP_PORT" 2>/dev/null
    sleep 0.2
}
trap cleanup EXIT

mkdir -p "$WORK/www"
[ -f "$WORK/www/bench$PAYLOAD_MIB.bin" ] || \
    dd if=/dev/urandom of="$WORK/www/bench$PAYLOAD_MIB.bin" \
       bs=1M count="$PAYLOAD_MIB" status=none

# Flat JSON: accepted by ssr-server, our client (listen_port) and the C
# client (flat local_port, config_json.c backward-compat branch).
write_cfg() { # path socks_port
    cat > "$1" <<EOF
{
  "server": "127.0.0.1",
  "server_port": $SRV_PORT,
  "method": "$METHOD",
  "protocol": "$PROTOCOL",
  "protocol_param": "",
  "obfs": "$OBFS",
  "obfs_param": "",
  "password": "$PASSWORD",
  "timeout": 60,
  "udp": false,
  "local_address": "127.0.0.1",
  "listen_port": $2,
  "local_port": $2
}
EOF
}

write_cfg "$WORK/srv.json" 0
write_cfg "$WORK/cli_c.json" "$C_PORT"
write_cfg "$WORK/cli_r.json" "$R_PORT"

wait_port() { # port timeout_s
    local deadline=$(( $(date +%s) + $2 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
            exec 3>&- 3<&-; return 0
        fi
        sleep 0.15
    done
    return 1
}

# ---- source HTTP server (reused if something already serves the payload) --
(cd "$WORK/www" && exec python3 -m http.server "$HTTP_PORT" \
    --bind 127.0.0.1 >/dev/null 2>&1) &
SRC_PID=$!
sleep 0.5
curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$HTTP_PORT/bench$PAYLOAD_MIB.bin" -r 0-0 \
    || die "local HTTP source did not come up"

# ---- ssr-server -----------------------------------------------------------
"$SSR_SERVER" -c "$WORK/srv.json" >"$WORK/srv.log" 2>&1 &
SRV_PID=$!
wait_port "$SRV_PORT" 8 || die "ssr-server did not open $SRV_PORT"
sleep 0.5

clk=$(getconf CLK_TCK)
pid_cpu() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

run_client() { # tag binary socks_port
    local tag="$1" bin="$2" port="$3" cfg="$WORK/cli_$1.json"
    "$bin" -c "$cfg" >"$WORK/$tag.log" 2>&1 &
    local cpid=$!
    if ! wait_port "$port" 10; then
        kill -9 "$cpid" 2>/dev/null
        echo "$tag FAILED_TO_START"
        return 1
    fi
    sleep 0.5

    local walls=() cpus=()
    for i in $(seq 1 "$RUNS"); do
        local c0 w0 t0
        c0=$(pid_cpu "$cpid")
        t0=$(date +%s.%N)
        local total
        total=$(curl -s -o /dev/null -w '%{time_total}' --max-time 120 \
            --socks5-hostname "127.0.0.1:$port" \
            "http://127.0.0.1:$HTTP_PORT/bench$PAYLOAD_MIB.bin") || total=""
        local t1 c1
        t1=$(date +%s.%N)
        c1=$(pid_cpu "$cpid")
        if [ -z "$total" ] || [ -z "$c1" ]; then
            echo "$tag run$i FAILED"
            kill -9 "$cpid" 2>/dev/null
            return 1
        fi
        # curl's time_total is authoritative for wall; CPU from ticks.
        walls+=("$total")
        cpus+=("$(awk -v a="$c1" -v b="$c0" -v k="$clk" 'BEGIN{printf "%.3f",(a-b)/k}')")
        echo "  $tag run$i: wall=${total}s cpu=${cpus[-1]}s" >&2
    done
    kill -9 "$cpid" 2>/dev/null
    wait "$cpid" 2>/dev/null

    # median wall (RUNS is odd:3 by default); CPU% = cpu/wall for that run
    # set aggregated over all runs (median pair by wall order).
    local med_wall med_cpu
    med_wall=$(printf '%s\n' "${walls[@]}" | sort -n | sed -n "2p")
    [ -n "$med_wall" ] || med_wall=$(printf '%s\n' "${walls[@]}" | sort -n | head -1)
    # CPU% of the median run: pick run whose wall == median
    med_cpu=$(awk -v m="$med_wall" -v c0="${cpus[0]}" -v c1="${cpus[1]:-0}" -v c2="${cpus[2]:-0}" \
        -v w0="${walls[0]}" -v w1="${walls[1]:-0}" -v w2="${walls[2]:-0}" \
        'BEGIN{
            if (w1==m) c=c1; else if (w2==m) c=c2; else c=c0;
            printf "%.1f", (c/m)*100
        }')
    local mbps
    mbps=$(awk -v w="$med_wall" -v p="$PAYLOAD_MIB" 'BEGIN{printf "%.1f", p/w}')
    echo "$tag $mbps $med_wall $med_cpu"
}

echo "== P2 bench: $METHOD/$PROTOCOL/$OBFS, ${PAYLOAD_MIB}MiB x $RUNS =="
echo "server=$SSR_SERVER c=$C_CLIENT rust=$RUST_CLIENT"

c_out=$(run_client c "$C_CLIENT" "$C_PORT") || die "C client run failed"
r_out=$(run_client r "$RUST_CLIENT" "$R_PORT") || die "rust client run failed"
echo "$c_out"; echo "$r_out"

read -r _ C_MBPS C_WALL C_CPU <<<"$c_out"
read -r _ R_MBPS R_WALL R_CPU <<<"$r_out"

VERDICT=$(awk -v c="$C_MBPS" -v r="$R_MBPS" -v cc="$C_CPU" -v rc="$R_CPU" \
    'BEGIN{
        t=r/c; cpu=rc/cc;
        ok1=(t>=0.9)?"PASS":"FAIL"; ok2=(cpu<=1.5)?"PASS":"FAIL";
        printf "throughput rust/C=%.2f%% (%s, need >=90%%)  cpu rust/C=%.2fx (%s, need <=1.5x)", t*100, ok1, cpu, ok2
    }')
echo "$VERDICT"

# ---- append to BENCH.md ---------------------------------------------------
{
    echo ""
    echo "## 4. P2 end-to-end vs C client ($(date +%F))"
    echo ""
    echo "| field | value |"
    echo "|---|---|"
    echo "| config | $METHOD / $PROTOCOL / $OBFS, loopback |"
    echo "| payload | ${PAYLOAD_MIB} MiB random file x $RUNS runs, median |"
    echo "| server | $SSR_SERVER ($(sha256sum "$SSR_SERVER" | cut -c1-12)) |"
    echo "| C client | $C_CLIENT ($(sha256sum "$C_CLIENT" | cut -c1-12)) |"
    echo "| Rust client | $RUST_CLIENT ($(sha256sum "$RUST_CLIENT" | cut -c1-12)) |"
    echo ""
    echo "| client | throughput MiB/s | median wall s | CPU % |"
    echo "|---|---|---|---|"
    echo "| C | $C_MBPS | $C_WALL | $C_CPU |"
    echo "| Rust | $R_MBPS | $R_WALL | $R_CPU |"
    echo ""
    echo "**Result**: throughput rust/C = $(awk -v c="$C_MBPS" -v r="$R_MBPS" 'BEGIN{printf "%.1f%%", r/c*100}') (target >= 90%),"
    echo "CPU rust/C = $(awk -v cc="$C_CPU" -v rc="$R_CPU" 'BEGIN{printf "%.2fx", rc/cc}') (target <= 1.5x) — $VERDICT"
} >> "$REPO/BENCH.md"

echo "appended to BENCH.md"
