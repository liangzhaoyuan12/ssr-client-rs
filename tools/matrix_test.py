#!/usr/bin/env python3
# Dev harness: end-to-end check of every cipher/obfs/protocol combination against a
# local ssr-server and a purely local HTTP target (no internet needed).
# Usage: python3 tools/matrix_test.py [--ref-c]   (--ref-c runs the C client as control)
# Requires: /opt/ssr/ssr-server, optionally /opt/ssr/ssr-client, and a release build.
"""End-to-end matrix test: run the local ssr-server + our Rust client for each
(cipher method x obfs x protocol) combination and request a purely LOCAL http
target, so the test needs no internet and is fully deterministic.

Usage: python3 /tmp/matrix_test.py
Writes results to /tmp/matrix_results.json
"""
import json
import os
import signal
import subprocess
import sys
import time

SSR_SERVER = "/opt/ssr/ssr-server"
RUST_CLIENT = "/home/liangzhaoyuan12/work/rs/ssr-client-rs/target/release/ssr_client"
C_CLIENT = "/opt/ssr/ssr-client"

PASSWORD = "test-password"
SRV_PORT = 18388
CLI_PORT = 18903
TARGET_PORT = 18080  # local python http.server

METHODS = [
    "none", "table", "rc4", "rc4-md5", "rc4-md5-6",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
    "salsa20", "chacha20", "chacha20-ietf",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
]
OBFS_LIST = ["plain", "http_simple", "http_post", "http_mix", "tls1.2_ticket_auth"]
PROTOCOLS = ["auth_aes128_sha1", "auth_aes128_md5", "auth_sha1_v4", "auth_chain_a"]


def write_server_cfg(method, protocol, obfs, path):
    cfg = {
        "password": PASSWORD,
        "method": method,
        "protocol": protocol,
        "protocol_param": "",
        "obfs": obfs,
        "obfs_param": "",
        "udp": False,
        "idle_timeout": 300,
        "connect_timeout": 6,
        "udp_timeout": 6,
        "server_settings": {"listen_address": "127.0.0.1", "listen_port": SRV_PORT},
    }
    with open(path, "w") as fh:
        json.dump(cfg, fh)


def write_client_cfg(method, protocol, obfs, path, port=CLI_PORT):
    cfg = {
        "password": PASSWORD,
        "method": method,
        "protocol": protocol,
        "protocol_param": "",
        "obfs": obfs,
        "obfs_param": "",
        "udp": False,
        "client_settings": {
            "server": "127.0.0.1",
            "server_port": SRV_PORT,
            "listen_address": "127.0.0.1",
            "listen_port": port,
        },
    }
    with open(path, "w") as fh:
        json.dump(cfg, fh)


def kill_all():
    subprocess.run(["killall", "ssr_client", "ssr-client", "ssr-server"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.4)


def probe(port, timeout=8):
    """Return the HTTP status code through the SOCKS5 proxy, or 'ERR'."""
    r = subprocess.run(
        ["curl", "-s", "-x", f"socks5h://127.0.0.1:{port}",
         f"http://127.0.0.1:{TARGET_PORT}/", "--max-time", str(timeout),
         "-o", "/dev/null", "-w", "%{http_code}"],
        capture_output=True, text=True)
    return r.stdout.strip() or "ERR"


def run_case(method, protocol, obfs, client_bin, client_cfg_writer):
    write_server_cfg(method, protocol, obfs, "/tmp/mx_server.json")
    client_cfg_writer(method, protocol, obfs, "/tmp/mx_client.json")
    kill_all()
    subprocess.Popen([SSR_SERVER, "-c", "/tmp/mx_server.json"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    time.sleep(0.8)
    log = open("/tmp/mx_client.log", "w")
    subprocess.Popen([client_bin, "-c", "/tmp/mx_client.json"] if client_bin == RUST_CLIENT
                     else [client_bin, "-c", "/tmp/mx_client.json"],
                     stdout=log, stderr=log, start_new_session=True)
    time.sleep(2.5)
    code = probe(CLI_PORT)
    log.close()
    kill_all()
    # capture a client-side error message if the client refused to start
    detail = ""
    try:
        with open("/tmp/mx_client.log") as fh:
            txt = fh.read()
        for line in txt.splitlines():
            if "Unsupported" in line or "Error" in line or "error" in line:
                detail = line.strip()[:110]
                break
    except OSError:
        pass
    return code, detail


def main():
    ref = "--ref-c" in sys.argv
    client_bin = C_CLIENT if ref else RUST_CLIENT
    client_cfg_writer = (lambda a, b, c, p: write_client_cfg(a, b, c, p))
    tag = "C-REF" if ref else "RUST"
    out_path = "/tmp/matrix_c.json" if ref else "/tmp/matrix_results.json"
    print(f"client under test: {tag} ({client_bin})")

    # local http target
    os.makedirs("/tmp/mx_www", exist_ok=True)
    with open("/tmp/mx_www/index.html", "w") as fh:
        fh.write("matrix-ok\n")
    subprocess.Popen([sys.executable, "-m", "http.server", str(TARGET_PORT),
                      "--bind", "127.0.0.1", "--directory", "/tmp/mx_www"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    time.sleep(1.0)
    print(f"local target: http://127.0.0.1:{TARGET_PORT}/")

    results = []

    print("\n=== cipher method matrix (protocol=auth_aes128_sha1, obfs=tls1.2_ticket_auth) ===")
    for m in METHODS:
        code, detail = run_case(m, "auth_aes128_sha1", "tls1.2_ticket_auth",
                                client_bin, client_cfg_writer)
        results.append({"axis": "cipher", "method": m,
                        "protocol": "auth_aes128_sha1",
                        "obfs": "tls1.2_ticket_auth", "http": code, "detail": detail})
        print(f"  {m:26s} HTTP {code:4s} {detail}")

    print("\n=== obfs matrix (cipher=aes-256-cfb, protocol=auth_aes128_sha1) ===")
    for o in OBFS_LIST:
        code, detail = run_case("aes-256-cfb", "auth_aes128_sha1", o,
                                client_bin, client_cfg_writer)
        results.append({"axis": "obfs", "method": "aes-256-cfb",
                        "protocol": "auth_aes128_sha1", "obfs": o,
                        "http": code, "detail": detail})
        print(f"  {o:26s} HTTP {code:4s} {detail}")

    print("\n=== protocol matrix (cipher=aes-256-cfb, obfs=tls1.2_ticket_auth) ===")
    for p in PROTOCOLS:
        code, detail = run_case("aes-256-cfb", p, "tls1.2_ticket_auth",
                                client_bin, client_cfg_writer)
        results.append({"axis": "protocol", "method": "aes-256-cfb",
                        "protocol": p, "obfs": "tls1.2_ticket_auth",
                        "http": code, "detail": detail})
        print(f"  {p:26s} HTTP {code:4s} {detail}")

    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2)
    kill_all()
    ok = sum(1 for r in results if r["http"] == "200")
    print(f"\n=== {tag}: {ok}/{len(results)} passed -> {out_path} ===")


if __name__ == "__main__":
    main()
