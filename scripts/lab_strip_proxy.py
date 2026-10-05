"""Lab STRIPTLS test proxy: forwards client<->server but rewrites the
STARTTLS advertisement out of server responses (same length preserved).

Usage: python3 scripts/lab_strip_proxy.py <listen_port> <upstream_port>
Serves ONE connection pair, then exits. Lab use only.
"""
from __future__ import annotations

import socket
import sys
import threading


def pipe(a: socket.socket, b: socket.socket, flt=None) -> None:
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            if flt:
                d = flt(d)
            b.sendall(d)
    except Exception:
        pass
    try:
        b.shutdown(socket.SHUT_WR)
    except Exception:
        pass


def main() -> int:
    listen, upstream = int(sys.argv[1]), int(sys.argv[2])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", listen))
    srv.listen(1)
    srv.settimeout(30)
    try:
        client, _ = srv.accept()
    except socket.timeout:
        return 1
    up = socket.create_connection(("127.0.0.1", upstream), timeout=8)
    t1 = threading.Thread(target=pipe, args=(client, up))
    t2 = threading.Thread(target=pipe, args=(up, client,
                                             lambda d: d.replace(b"STARTTLS", b"XXXXXXXX")))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
