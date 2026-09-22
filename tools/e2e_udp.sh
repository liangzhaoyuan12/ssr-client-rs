#!/usr/bin/env bash
# UDP e2e driver: start local ssr-server + our Rust client with UDP enabled,
# run tests/e2e/test_udp_e2e.py against them, tear everything down.
#
# Usage:
#   tools/e2e_udp.sh              # default combo (auth_chain_a + aes-256-cfb)
#   tools/e2e_udp.sh --all        # all three known-good combos
#
# Combo args (for a custom run):
#   tools/e2e_udp.sh <method> <protocol> <srv_port> <socks_port> [obfs]
#
# Self-contained: configs are generated in a mktemp dir, nothing under /tmp is
# read from a previous session. Requires /opt/ssr/ssr-server and a built client
# (cargo build if target/debug/ssr_client is missing).
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SSR_SERVER="${SSR_SERVER:-/opt/ssr/ssr-server}"
CLIENT="${SSR_CLIENT:-$REPO/target/debug/ssr_client}"
WORK="$(mktemp -d /tmp/ssr_e2e_udp.XXXXXX)"
PASSWORD="test_password_123"
declare -a PIDS=()
declare -a LOGS=()

cleanup() {
    local rc=$?
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    if [ "$rc" -ne 0 ]; then
        echo "--- cleanup: failing run logs kept at $WORK ---"
        for f in "${LOGS[@]:-}"; do echo "== $f =="; tail -20 "$f"; done
    else
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

die() { echo "SKIP/FAIL: $*" >&2; exit 1; }

[ -x "$SSR_SERVER" ] || die "ssr-server not found: $SSR_SERVER"
if [ ! -x "$CLIENT" ]; then
    echo "client binary missing, building..."
    (cd "$REPO" && cargo build --quiet) || die "cargo build failed"
fi

wait_port() { # wait_port <tcp|udp> <port> <label>
    local proto=$1 port=$2 label=$3 i flag
    # NOTE: this ss build rejects `-tcp`; the flag is just `-t`.
    if [ "$proto" = udp ]; then flag="-ulnt"; else flag="-lnt"; fi
    for i in $(seq 1 50); do
        if ss "$flag" 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        sleep 0.2
    done
    die "$label port $port did not come up"
}

run_combo() { # run_combo <method> <protocol> <srv_port> <socks_port> [obfs]
    local method=$1 proto=$2 srv_port=$3 socks_port=$4 obfs=${5:-plain}
    local srv_cfg="$WORK/srv_${method}_${proto}_${srv_port}.json"
    local cli_cfg="$WORK/cli_${method}_${proto}_${srv_port}.json"
    local srv_log="$WORK/srv_${srv_port}.log"
    local cli_log="$WORK/cli_${srv_port}.log"

    cat > "$srv_cfg" <<EOF
{
    "server": "127.0.0.1",
    "server_port": $srv_port,
    "method": "$method",
    "protocol": "$proto",
    "protocol_param": "",
    "obfs": "$obfs",
    "obfs_param": "",
    "password": "$PASSWORD",
    "timeout": 60,
    "udp": true
}
EOF
    cat > "$cli_cfg" <<EOF
{
    "server": "127.0.0.1",
    "server_port": $srv_port,
    "method": "$method",
    "protocol": "$proto",
    "protocol_param": "",
    "obfs": "$obfs",
    "obfs_param": "",
    "password": "$PASSWORD",
    "local_address": "127.0.0.1",
    "listen_port": $socks_port,
    "udp": true,
    "udp_timeout": 6
}
EOF

    echo "=== combo: $method + $proto + $obfs (server:$srv_port socks:$socks_port)"
    "$SSR_SERVER" -c "$srv_cfg" > "$srv_log" 2>&1 &
    PIDS+=($!); LOGS+=("$srv_log")
    wait_port udp "$srv_port" "server-udp"

    "$CLIENT" -c "$cli_cfg" > "$cli_log" 2>&1 &
    PIDS+=($!); LOGS+=("$cli_log")
    wait_port tcp "$socks_port" "client-tcp"
    wait_port udp "$socks_port" "client-udp"

    SOCKS_PORT="$socks_port" ECHO_PORT=$((socks_port + 600)) \
        python3 "$REPO/tests/e2e/test_udp_e2e.py" \
        || die "test_udp_e2e.py failed for $method+$proto (logs: $WORK)"

    # tear down this combo's processes before the next one
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    PIDS=()
    wait 2>/dev/null
    sleep 0.3
    echo "PASS: $method + $proto + $obfs"
}

if [ "${1:-}" = "--all" ]; then
    run_combo aes-256-cfb  auth_chain_a     18396 19912
    run_combo aes-256-cfb  auth_aes128_sha1 18397 19913
    run_combo aes-128-gcm  origin           18398 19914
    echo "UDP_E2E_ALL_PASS"
else
    run_combo "${1:-aes-256-cfb}" "${2:-auth_chain_a}" \
              "${3:-18396}" "${4:-19912}" "${5:-plain}"
    echo "UDP_E2E_PASS"
fi
