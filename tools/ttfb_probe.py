#!/usr/bin/env python3
"""TTFB probe (GOAL 3.4): SOCKS5 connect -> method reply -> CONNECT success
reply -> first echo byte, through the local C server, for any client binary.

Usage:
  python3 tools/ttfb_probe.py --client target/release/ssr_client --tag after
  python3 tools/ttfb_probe.py --client /tmp/ssr_before/target/release/ssr_client --tag before

Prints one JSON line per method (median/p90 of 30 runs, ms):
  {"tag": ..., "method": ..., "n": 30,
   "method_reply_ms": ..., "connect_reply_ms": ..., "first_echo_ms": ...,
   "connect_first_ms": ...}   # connect_reply incl. tunnel setup; first_echo = RTT after

`connect_first_ms` = connect-reply median minus method-reply median is NOT
reported; stages are measured back-to-back per run and summed as total_ms.
The FIRST run of each client is reported separately (client pays its lazy
one-time env build there when caching is absent from the path).
"""
import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

SRV_PORT = 20171
SOCKS_PORT = 20172
ECHO_PORT = 20173


def start_echo():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO_PORT))
    srv.listen(64)

    def echo(c):
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def accept_loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(c,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()


def write_cfg(method, path, is_server):
    cfg = {
        "server": "127.0.0.1",
        "server_port": SRV_PORT,
        "local_address": "127.0.0.1",
        "listen_port": SOCKS_PORT,
        "local_port": SOCKS_PORT,
        "password": "ttfb_pw_1",
        "method": method,
        "protocol": "origin",
        "protocol_param": "",
        "obfs": "plain",
        "obfs_param": "",
        "timeout": 60,
        "udp": False,
        "idle_timeout": 30,
    }
    with open(path, "w") as fh:
        json.dump(cfg, fh, indent=2)


def wait_port(port, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def one_run():
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), 5)
    s.settimeout(10)
    try:
        t0 = time.perf_counter()
        s.sendall(b"\x05\x01\x00")
        m = s.recv(2)
        assert m == b"\x05\x00", f"method reply: {m!r}"
        t1 = time.perf_counter()
        req = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + ECHO_PORT.to_bytes(2, "big")
        s.sendall(req)
        head = b""
        while len(head) < 4:
            head += s.recv(4 - len(head))
        assert head[0] == 5 and head[1] == 0, f"connect reply: {head!r}"
        # addr (4/16/1+len) + port (2)
        extra = (4 if head[3] == 1 else 16) + 2
        if head[3] == 3:
            extra = s.recv(1)[0] + 3
        while len(head) < 4 + extra:
            head += s.recv(4 + extra - len(head))
        t2 = time.perf_counter()
        s.sendall(b"x")
        b = s.recv(1)
        assert b == b"x", f"echo: {b!r}"
        t3 = time.perf_counter()
        return ((t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3)
    finally:
        s.close()


def measure(client, tag, server_bin, runs):
    out = {}
    procs = []
    tmp = tempfile.mkdtemp(prefix="ttfb_")
    srv_cfg = os.path.join(tmp, "srv.json")
    cli_cfg = os.path.join(tmp, "cli.json")
    write_cfg(out_method := "aes-256-cfb", srv_cfg, True)  # placeholder, set below
    results = {}
    for method in ("table", "aes-256-cfb"):
        write_cfg(method, srv_cfg, True)
        write_cfg(method, cli_cfg, False)
        with open(os.path.join(tmp, "srv.log"), "w") as fh:
            srv = subprocess.Popen([server_bin, "-c", srv_cfg], stdout=fh, stderr=subprocess.STDOUT)
        assert wait_port(SRV_PORT), "server did not bind"
        with open(os.path.join(tmp, "cli.log"), "w") as fh:
            cli = subprocess.Popen([client, "-c", cli_cfg], stdout=fh, stderr=subprocess.STDOUT)
        assert wait_port(SOCKS_PORT), "client did not bind"
        procs = [srv, cli]
        try:
            samples = [one_run() for _ in range(runs)]
        finally:
            # Crash-safe: a failed sample must not leak a server/client
            # pair into the next measurement (observed stale listeners
            # poisoning later runs).
            for p in procs:
                try:
                    p.kill()
                except OSError:
                    pass
            for p in procs:
                try:
                    p.wait()
                except OSError:
                    pass
        first = samples[0]
        m = [s[0] for s in samples]
        c = [s[1] for s in samples]
        e = [s[2] for s in samples]
        tot = [sum(s) for s in samples]
        results[method] = {
            "tag": tag,
            "method": method,
            "n": runs,
            "method_reply_ms": round(statistics.median(m), 3),
            "connect_reply_ms": round(statistics.median(c), 3),
            "first_echo_ms": round(statistics.median(e), 3),
            "total_ms": round(statistics.median(tot), 3),
            "p90_total_ms": round(sorted(tot)[int(runs * 0.9) - 1], 3),
            "first_run_total_ms": round(sum(first), 3),
        }
        for p in procs:
            p.kill()
        for p in procs:
            p.wait()
        time.sleep(0.3)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--server", default="/opt/ssr/ssr-server")
    ap.add_argument("--runs", type=int, default=30)
    args = ap.parse_args()

    start_echo()
    results = measure(args.client, args.tag, args.server, args.runs)
    for method, r in results.items():
        print(json.dumps(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
