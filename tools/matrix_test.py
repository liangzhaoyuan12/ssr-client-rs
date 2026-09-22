#!/usr/bin/env python3
"""GOALS T4: e2e matrix — local ssr-server + our client, purely local target.

Combination strategy (GOALS T4, three axes + UDP):
  cipher  : every implemented cipher x origin  + plain   (21, unimplemented -> SKIP)
  protocol: aes-256-cfb        x <protocol>    + plain   (14; chain_f uses aes-128-cfb)
  obfs    : aes-256-cfb        x auth_aes128_sha1 + <obfs> (6)
  udp     : delegated to tools/e2e_udp.sh --all          (3)

Usage:
  python3 tools/matrix_test.py            # all axes
  python3 tools/matrix_test.py --ref-c    # C client as control
  python3 tools/matrix_test.py --axis protocol

Outputs:
  tests/e2e/RESULTS.md           markdown table, dated, with server binary hash
  tests/e2e/matrix_results.json  machine-readable dump

Requires: /opt/ssr/ssr-server and a built client (release preferred, else debug).
"""
import argparse
import datetime
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSR_SERVER = os.environ.get("SSR_SERVER", "/opt/ssr/ssr-server")
C_CLIENT = os.environ.get("C_CLIENT", "/opt/ssr/ssr-client")
RUST_CLIENT = os.environ.get(
    "MATRIX_CLIENT",
    os.path.join(REPO, "target/release/ssr_client")
    if os.path.exists(os.path.join(REPO, "target/release/ssr_client"))
    else os.path.join(REPO, "target/debug/ssr_client"),
)

PASSWORD = "test-password"
SRV_PORT = 18388
CLI_PORT = 18903
TARGET_PORT = 18080
WORK = "/tmp/ssr_matrix"

# GOALS: implemented stream (16) + AEAD (5) = 21 runnable ciphers.
CIPHERS = [
    "none", "table", "rc4", "rc4-md5", "rc4-md5-6",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "bf-cfb", "salsa20", "chacha20", "chacha20-ietf",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
]
# GOALS: unimplemented ciphers are recorded as SKIP with reason, never run.
CIPHER_SKIP = {
    "camellia-128-cfb": "client not implemented (server supports)",
    "camellia-192-cfb": "client not implemented (server supports)",
    "camellia-256-cfb": "client not implemented (server supports)",
    "cast5-cfb": "server itself does not support (C client fails too)",
    "idea-cfb": "server itself does not support (C client fails too)",
    "rc2-cfb": "server itself does not support (C client fails too)",
    "seed-cfb": "server itself does not support (C client fails too)",
    # Server-side mbedTLS refuses it: "Cipher unsupported currently is not
    # supported by mbed TLS library" (observed in matrix run 2026-09-23).
    "des-cfb": "server mbedTLS does not support des-cfb",
}
PROTOCOLS = [
    "origin", "verify_simple", "auth_simple", "auth_sha1",
    "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
    "auth_chain_a", "auth_chain_b", "auth_chain_c",
    "auth_chain_d", "auth_chain_e", "auth_chain_f",
]
OBFS_LIST = [
    "plain", "http_simple", "http_post", "http_mix",
    "tls1.2_ticket_auth", "tls1.2_ticket_fastauth",
]
# auth_chain_f + key_len>16 SIGBUSes the C server (stack overflow in
# auth_chain_f_set_server_info): see PROGRESS. Use a 16-byte-key cipher.
PROTOCOL_METHOD_OVERRIDES = {"auth_chain_f": "aes-128-cfb"}

_pids = []
# The local HTTP target must OUTLIVE per-case kill_tracked(); track it apart.
_target_pid = None


def wait_tcp(port, pid=None, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pid is not None and proc_alive(pid) is False:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def proc_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def kill_tracked():
    for pid in _pids:
        try:
            os.kill(pid, 15)
        except OSError:
            pass
    time.sleep(0.3)
    for pid in _pids:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    _pids.clear()
    time.sleep(0.2)


def server_hash():
    try:
        with open(SSR_SERVER, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:12]
    except OSError:
        return "missing"


def write_cfg(method, protocol, obfs, path, is_server):
    """Flat keys: proven to work with /opt/ssr/ssr-server and our client
    (nested *_settings also supported by our parser, flat is simpler)."""
    cfg = {
        "server": "127.0.0.1",
        "server_port": SRV_PORT,
        "method": method,
        "protocol": protocol,
        "protocol_param": "",
        "obfs": obfs,
        "obfs_param": "",
        "password": PASSWORD,
        "timeout": 60,
        "udp": False,
    }
    if not is_server:
        cfg["local_address"] = "127.0.0.1"
        cfg["listen_port"] = CLI_PORT
    with open(path, "w") as fh:
        json.dump(cfg, fh, indent=2)


def ensure_target():
    """Local HTTP target serving 'matrix-ok'; reuse an existing listener if it
    already serves the marker, else spawn our own."""
    marker = "matrix-ok"

    def fetch():
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "2",
                 f"http://127.0.0.1:{TARGET_PORT}/"],
                capture_output=True, text=True, timeout=4)
            return marker in r.stdout
        except Exception:
            return False

    if fetch():
        print(f"reusing local target on {TARGET_PORT}")
        return True

    os.makedirs(f"{WORK}/www", exist_ok=True)
    with open(f"{WORK}/www/index.html", "w") as fh:
        fh.write(marker + "\n")
    global _target_pid
    proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(TARGET_PORT),
         "--bind", "127.0.0.1", "--directory", f"{WORK}/www"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    _target_pid = proc.pid
    for _ in range(20):
        if fetch():
            print(f"local target up on {TARGET_PORT}")
            return True
        time.sleep(0.25)
    print(f"ERROR: cannot serve local target on {TARGET_PORT} "
          "(port busy with a different service; free it and re-run)")
    return False


def probe():
    """Return '200' only if the proxied fetch returned the marker body."""
    try:
        r = subprocess.run(
            ["curl", "-s", "-x", f"socks5h://127.0.0.1:{CLI_PORT}",
             f"http://127.0.0.1:{TARGET_PORT}/", "--max-time", "5"],
            capture_output=True, text=True, timeout=8)
        if "matrix-ok" in r.stdout:
            return "200"
        return "BADBODY" if r.returncode == 0 else "ERR"
    except Exception:
        return "ERR"


def tail_errors(path, limit=110):
    try:
        with open(path) as fh:
            txt = fh.read()
    except OSError:
        return ""
    for line in txt.splitlines():
        low = line.lower()
        if "error" in low or "unsupported" in low or "panic" in low:
            return line.strip()[:limit]
    return ""


def run_case(method, protocol, obfs, client_bin):
    srv_cfg = f"{WORK}/srv.json"
    cli_cfg = f"{WORK}/cli.json"
    cli_log = f"{WORK}/client.log"
    srv_log = f"{WORK}/server.log"
    write_cfg(method, protocol, obfs, srv_cfg, is_server=True)
    write_cfg(method, protocol, obfs, cli_cfg, is_server=False)

    kill_tracked()
    with open(srv_log, "w") as fh:
        srv = subprocess.Popen([SSR_SERVER, "-c", srv_cfg],
                               stdout=fh, stderr=subprocess.STDOUT,
                               start_new_session=True)
    _pids.append(srv.pid)
    if not wait_tcp(SRV_PORT, pid=srv.pid, timeout=6):
        kill_tracked()
        return "SRVFAIL", tail_errors(srv_log)

    with open(cli_log, "w") as fh:
        cli = subprocess.Popen([client_bin, "-c", cli_cfg],
                               stdout=fh, stderr=subprocess.STDOUT,
                               start_new_session=True)
    _pids.append(cli.pid)
    if not wait_tcp(CLI_PORT, pid=cli.pid, timeout=6):
        kill_tracked()
        return "CLIFAIL", tail_errors(cli_log)

    code = probe()
    detail = "" if code == "200" else (tail_errors(cli_log) or tail_errors(srv_log))
    kill_tracked()
    return code, detail


def build_cases(axis):
    cases = []  # (axis_name, method, protocol, obfs, note)
    if axis in ("all", "cipher"):
        for m in CIPHERS:
            # AEAD methods negotiate origin+plain (client downgrades; keep the
            # server in the same shape as PROGRESS' passing AEAD combo).
            proto = "origin"
            cases.append(("cipher", m, proto, "plain", ""))
        for m, why in CIPHER_SKIP.items():
            cases.append(("cipher", m, "origin", "plain", f"SKIP: {why}"))
    if axis in ("all", "protocol"):
        for p in PROTOCOLS:
            m = PROTOCOL_METHOD_OVERRIDES.get(p, "aes-256-cfb")
            note = "uses aes-128-cfb (C server SIGBUS with key_len>16)" \
                if p in PROTOCOL_METHOD_OVERRIDES else ""
            cases.append(("protocol", m, p, "plain", note))
    if axis in ("all", "obfs"):
        for o in OBFS_LIST:
            cases.append(("obfs", "aes-256-cfb", "auth_aes128_sha1", o, ""))
    return cases


def run_udp_axis(results):
    """Delegate the 3 UDP combos to the in-repo driver (GOALS T1 asset)."""
    script = os.path.join(REPO, "tools/e2e_udp.sh")
    if not os.path.exists(script):
        return 0, 0
    print("\n=== udp axis (tools/e2e_udp.sh --all) ===")
    r = subprocess.run(["bash", script, "--all"],
                       capture_output=True, text=True, timeout=180)
    ok = "UDP_E2E_ALL_PASS" in (r.stdout + r.stderr)
    for name, note in [
        ("aes-256-cfb+auth_chain_a", ""),
        ("aes-256-cfb+auth_aes128_sha1", ""),
        ("aes-128-gcm+origin (AEAD)", ""),
    ]:
        results.append({"axis": "udp", "method": name, "protocol": "",
                        "obfs": "", "http": "200" if ok else "ERR",
                        "detail": note})
        print(f"  {name:34s} {'PASS' if ok else 'FAIL'}")
    return (3 if ok else 0), 3


def write_results_md(results, tag, skipped, out_path):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed = sum(1 for r in results if r["http"] == "200")
    total = len(results)
    lines = [
        "# e2e matrix results",
        "",
        f"- date: {now}",
        f"- client: {tag} ({os.path.relpath(RUST_CLIENT, REPO) if tag != 'C-REF' else C_CLIENT})",
        f"- server: {SSR_SERVER} sha256[:12]={server_hash()}",
        f"- result: **{passed}/{total} passed**"
        + (f", {skipped} skipped (not run)" if skipped else ""),
        "",
        "| axis | method | protocol | obfs | result | note |",
        "|------|--------|----------|------|--------|------|",
    ]
    for r in results:
        if r["http"] == "SKIP":
            res, note = "SKIP", r["detail"]
        elif r["http"] == "200":
            res, note = "PASS", r.get("detail", "")
        else:
            res, note = f"FAIL({r['http']})", r.get("detail", "")
        lines.append(f"| {r['axis']} | {r['method']} | {r['protocol']} "
                     f"| {r['obfs']} | {res} | {note} |")
    lines.append("")
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref-c", action="store_true",
                    help="run the C client as control")
    ap.add_argument("--axis", default="all",
                    choices=["all", "cipher", "protocol", "obfs", "udp"])
    args = ap.parse_args()

    client_bin = C_CLIENT if args.ref_c else RUST_CLIENT
    tag = "C-REF" if args.ref_c else "RUST"
    if not os.path.exists(client_bin):
        print(f"ERROR: client binary missing: {client_bin}\n"
              "hint: cargo build --release (or unset MATRIX_CLIENT)")
        return 2
    if not os.path.exists(SSR_SERVER):
        print(f"ERROR: ssr-server missing: {SSR_SERVER}")
        return 2
    os.makedirs(WORK, exist_ok=True)
    print(f"client under test: {tag} ({client_bin})")
    print(f"server: {SSR_SERVER} sha256[:12]={server_hash()}")

    if not ensure_target():
        return 2

    results = []
    skipped = 0
    cases = build_cases(args.axis)
    for i, (axis, method, protocol, obfs, note) in enumerate(cases, 1):
        if note.startswith("SKIP"):
            skipped += 1
            results.append({"axis": axis, "method": method,
                            "protocol": protocol, "obfs": obfs,
                            "http": "SKIP", "detail": note})
            print(f"[{i}/{len(cases)}] {method:26s} SKIP ({note})")
            continue
        code, detail = run_case(method, protocol, obfs, client_bin)
        results.append({"axis": axis, "method": method, "protocol": protocol,
                        "obfs": obfs, "http": code, "detail": detail})
        mark = "PASS" if code == "200" else f"FAIL({code})"
        print(f"[{i}/{len(cases)}] {method:18s} {protocol:18s} {obfs:22s} "
              f"{mark} {detail}")

    udp_ok = udp_total = 0
    if args.axis in ("all", "udp"):
        udp_ok, udp_total = run_udp_axis(results)
        skipped_udp = 0
    else:
        skipped_udp = None

    kill_tracked()
    # target cleanup: only the process WE spawned (never a pre-existing one)
    if _target_pid:
        try:
            os.kill(_target_pid, 9)
        except OSError:
            pass

    out_dir = os.path.join(REPO, "tests", "e2e")
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "RESULTS.md")
    json_path = os.path.join(out_dir, "matrix_results.json")
    write_results_md(results, tag, skipped, md_path)
    with open(json_path, "w") as fh:
        json.dump({"client": tag, "server_sha12": server_hash(),
                   "results": results}, fh, indent=2)

    ok = sum(1 for r in results if r["http"] == "200")
    total = len(results)
    print(f"\n=== {tag}: {ok}/{total} passed"
          + (f", {skipped} skipped" if skipped else "")
          + f" -> {os.path.relpath(md_path, REPO)} ===")
    ran = total - skipped
    return 0 if ok == ran else 1


if __name__ == "__main__":
    sys.exit(main())
