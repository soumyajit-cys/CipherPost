"""Lab mail servers for Item 3: REAL socket traffic, not synthetic generator output.

Runs minimal SMTP/IMAP/POP3 servers (plaintext + STARTTLS/STLS upgrade +
implicit TLS) on loopback mail ports. Each invocation serves ONE connection
with a scripted dialog, optionally upgrading to TLS mid-connection with the
given cert, TLS version range, and cipher string.

Usage:
  python3 scripts/lab_mail.py server <kind> <port> --cert C --key K [options]

kind: smtp | imap | pop3            (STARTTLS/STLS upgrade offered unless --no-starttls)
      smtp-implicit | imap-implicit | pop3-implicit   (TLS immediately)
options: --tlsmin 1.0|1.1|1.2|1.3  --tlsmax ...  --ciphers '...'  --no-starttls

The client side is openssl s_client / raw sockets (see docs/evidence/real-eval.md).
Captures: dumpcap on lo, filtered to the scenario port, classic pcap.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import threading

TLSMAP = {"1.0": ssl.TLSVersion.TLSv1, "1.1": ssl.TLSVersion.TLSv1_1,
          "1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def recv_line(f) -> str:
    data = f.readline()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def tls_context(cert: str, key: str, tlsmin: str, tlsmax: str, ciphers: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = TLSMAP[tlsmin]
    ctx.maximum_version = TLSMAP[tlsmax]
    if ciphers:
        ctx.set_ciphers(ciphers)
    return ctx


def smtp_dialog(conn: socket.socket, offer_starttls: bool, tls_ctx: ssl.SSLContext | None) -> None:
    f = conn.makefile("rwb")
    f.write(b"220 mail.lab.test ESMTP lab\r\n")
    f.flush()
    upgraded = False
    while True:
        line = recv_line(f).strip()
        if not line:
            return
        cmd = line.split()[0].upper()
        if cmd in ("EHLO", "HELO"):
            caps = ["250-mail.lab.test"]
            if offer_starttls and not upgraded:
                caps.append("250-STARTTLS")
            caps.append("250 AUTH PLAIN LOGIN")
            f.write(("\r\n".join(caps) + "\r\n").encode())
            f.flush()
        elif cmd == "STARTTLS" and offer_starttls and not upgraded:
            f.write(b"220 2.0.0 Ready to start TLS\r\n")
            f.flush()
            conn = tls_ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rwb")
            upgraded = True
        elif cmd == "AUTH":
            f.write(b"235 2.7.0 Authentication successful\r\n")
            f.flush()
        elif cmd == "QUIT":
            f.write(b"221 2.0.0 Bye\r\n")
            f.flush()
            return
        else:
            f.write(b"502 5.5.2 Command not recognized\r\n")
            f.flush()


def imap_dialog(conn: socket.socket, offer_starttls: bool, tls_ctx: ssl.SSLContext | None) -> None:
    f = conn.makefile("rwb")
    f.write(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] lab ready\r\n")
    f.flush()
    upgraded = False
    while True:
        line = recv_line(f).strip()
        if not line:
            return
        parts = line.split()
        if len(parts) < 2:
            continue
        tag, cmd = parts[0], parts[1].upper()
        if cmd == "CAPABILITY":
            caps = "* CAPABILITY IMAP4rev1 AUTH=PLAIN"
            if offer_starttls and not upgraded:
                caps += " STARTTLS"
            f.write(f"{caps}\r\n{tag} OK completed\r\n".encode())
            f.flush()
        elif cmd == "STARTTLS" and offer_starttls and not upgraded:
            f.write(f"{tag} OK Begin TLS negotiation now\r\n".encode())
            f.flush()
            conn = tls_ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rwb")
            upgraded = True
        elif cmd == "LOGIN":
            f.write(f"{tag} OK logged in\r\n".encode())
            f.flush()
        elif cmd == "LOGOUT":
            f.write(f"* BYE logging out\r\n{tag} OK completed\r\n".encode())
            f.flush()
            return
        else:
            f.write(f"{tag} BAD unknown\r\n".encode())
            f.flush()


def pop3_dialog(conn: socket.socket, offer_stls: bool, tls_ctx: ssl.SSLContext | None) -> None:
    f = conn.makefile("rwb")
    f.write(b"+OK lab ready\r\n")
    f.flush()
    upgraded = False
    while True:
        line = recv_line(f).strip()
        if not line:
            return
        cmd = line.split()[0].upper() if line.split() else ""
        if cmd == "CAPA":
            caps = "+OK Capability list follows\r\nUSER\r\n"
            if offer_stls and not upgraded:
                caps += "STLS\r\n"
            caps += "SASL PLAIN\r\n.\r\n"
            f.write(caps.encode())
            f.flush()
        elif cmd == "STLS" and offer_stls and not upgraded:
            f.write(b"+OK Begin TLS negotiation\r\n")
            f.flush()
            conn = tls_ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rwb")
            upgraded = True
        elif cmd in ("USER", "PASS"):
            f.write(b"+OK\r\n")
            f.flush()
        elif cmd == "QUIT":
            f.write(b"+OK Bye\r\n")
            f.flush()
            return
        else:
            f.write(b"-ERR unknown\r\n")
            f.flush()


DIALOGS = {"smtp": smtp_dialog, "imap": imap_dialog, "pop3": pop3_dialog}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server"])
    ap.add_argument("kind")
    ap.add_argument("port", type=int)
    ap.add_argument("--cert", default="")
    ap.add_argument("--key", default="")
    ap.add_argument("--tlsmin", default="1.2")
    ap.add_argument("--tlsmax", default="1.3")
    ap.add_argument("--ciphers", default=None)
    ap.add_argument("--no-starttls", action="store_true")
    args = ap.parse_args()

    implicit = args.kind.endswith("-implicit")
    base = args.kind.replace("-implicit", "")
    if base not in DIALOGS:
        print(f"unknown kind {args.kind}", file=sys.stderr)
        return 2

    tls_ctx = None
    if implicit or not args.no_starttls or True:
        if args.cert:
            tls_ctx = tls_context(args.cert, args.key, args.tlsmin, args.tlsmax, args.ciphers)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(5)
    srv.settimeout(1.0)
    served = 0
    # Serve connections until killed by timeout(1); the listen-check probe
    # consumes the first accept, so single-connection service is wrong.
    while True:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        try:
            with open("/tmp/opencode/maillab/srv_conns.log", "a") as _lf:
                _lf.write(f"accept {addr}\n")
        except Exception:
            pass
        except OSError:
            break
        try:
            c = conn
            if implicit:
                c = tls_ctx.wrap_socket(c, server_side=True)
            DIALOGS[base](c, not args.no_starttls, tls_ctx)
            served += 1
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as e:
            print(f"lab server: connection ended: {e}", file=sys.stderr)
        finally:
            # RST-close (SO_LINGER 0): guarantees connection teardown on the
            # wire so captures contain complete streams. Lab-only behavior,
            # documented in docs/evidence/real-eval.md.
            try:
                import struct as _st
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                _st.pack("ii", 1, 0))
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
