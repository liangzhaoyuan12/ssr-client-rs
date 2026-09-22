#!/usr/bin/env python3
"""UDP e2e: SOCKS5 UDP ASSOCIATE through our Rust client -> C ssr-server -> echo target.

Path: python app --UDP--> rust client --enc--> C server --plain--> local echo server
      and back.

Usage (normally driven by tools/e2e_udp.sh):
    SOCKS_PORT=19912 ECHO_PORT=20535 python3 test_udp_e2e.py

Checks, in order:
  1. SOCKS5 handshake + UDP ASSOCIATE reply (BND addr/port parse)
  2. IPv4-target datagram echo roundtrip (payload byte-identical)
  3. second datagram on same session (session reuse, no re-handshake)
  4. domain-target datagram (ATYP=3) roundtrip; response header must be the
     APP's own address — C behavior, udp_ssr_client.c:240 incoming_addr.
"""
import os
import socket
import struct
import sys
import threading

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "19912"))
ECHO_PORT = int(os.environ.get("ECHO_PORT", "20535"))


def echo_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", ECHO_PORT))
    s.settimeout(10)
    try:
        while True:
            data, addr = s.recvfrom(65535)
            s.sendto(data, addr)
    except socket.timeout:
        pass
    finally:
        s.close()


def main():
    t = threading.Thread(target=echo_server, daemon=True)
    t.start()

    # 1. SOCKS5 handshake
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(10)
    tcp.connect((SOCKS_HOST, SOCKS_PORT))
    tcp.sendall(b"\x05\x01\x00")
    resp = tcp.recv(2)
    assert resp == b"\x05\x00", f"method resp {resp!r}"

    # UDP ASSOCIATE (dst addr/port ignored per RFC)
    tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = tcp.recv(32)
    assert rep[0] == 5 and rep[1] == 0, f"associate rep {rep!r}"
    atyp = rep[3]
    if atyp == 1:
        bnd = socket.inet_ntoa(rep[4:8])
        bnd_port = struct.unpack("!H", rep[8:10])[0]
    elif atyp == 4:
        bnd = socket.inet_ntop(socket.AF_INET6, rep[4:20])
        bnd_port = struct.unpack("!H", rep[20:22])[0]
    else:
        raise SystemExit(f"bad atyp {atyp}")
    print(f"ASSOCIATE ok, BND={bnd}:{bnd_port}")

    # 2. IPv4-target datagram echo roundtrip
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(10)
    target = ("127.0.0.1", ECHO_PORT)
    payload = b"hello_udp_e2e"
    dg = b"\x00\x00\x00" + b"\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]) + payload
    udp.sendto(dg, (bnd, bnd_port))

    back, src = udp.recvfrom(65535)
    print(f"reply from {src}, {len(back)} bytes")
    assert back[0:3] == b"\x00\x00\x00", f"RSV/FRAG {back[:3]!r}"
    assert back[3] == 1, f"atyp {back[3]}"
    hdr = 10  # RSV/FRAG(3) + ATYP(1) + IPv4(4) + port(2)
    body = back[hdr:]
    print(f"payload={body!r}")
    assert body == payload, f"echo mismatch {body!r} != {payload!r}"

    # 3. second datagram to verify session reuse
    payload2 = b"second_datagram!!"
    dg2 = b"\x00\x00\x00" + b"\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1]) + payload2
    udp.sendto(dg2, (bnd, bnd_port))
    back2, _ = udp.recvfrom(65535)
    assert back2[hdr:] == payload2, f"second mismatch {back2[hdr:]!r}"
    print("session reuse ok")

    # 4. domain-target datagram (ATYP=3)
    payload3 = b"domain_target_ok"
    dom = b"localhost"
    dg3 = b"\x00\x00\x00" + b"\x03" + bytes([len(dom)]) + dom + struct.pack("!H", ECHO_PORT) + payload3
    udp.sendto(dg3, (bnd, bnd_port))
    back3, _ = udp.recvfrom(65535)
    # Per C (udp_ssr_client.c:240) the response address header is the APP's
    # own address (incoming_addr), not an echo of the target — app is v4 here.
    assert back3[3] == 1, f"resp atyp {back3[3]}"
    assert back3[4:8] == socket.inet_aton("127.0.0.1"), f"resp addr {back3[4:8]!r}"
    assert back3[hdr:] == payload3, f"domain mismatch {back3[hdr:]!r}"
    print("domain target ok (response header = app addr, C behavior)")

    tcp.close()
    udp.close()
    print("UDP_E2E_PASS")


if __name__ == "__main__":
    sys.exit(main())
