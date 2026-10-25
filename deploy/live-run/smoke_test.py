#!/usr/bin/env python3
"""Smoke test for the CipherPost live-run lab.

Checks that:
1. Postfix (SMTP) is reachable on 127.0.0.1:587.
2. Dovecot (IMAP) is reachable on 127.0.0.1:993.
3. CipherPost API is reachable on 127.0.0.1:8000.

Usage:
    python3 smoke_test.py
"""
import socket
import sys
import urllib.request

SERVICES = [
    ("Postfix SMTP", "127.0.0.1", 587),
    ("Dovecot IMAP", "127.0.0.1", 993),
]


def check_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_api(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return 200 <= r.status < 400
    except Exception:
        return False


def main() -> int:
    failures = 0
    for name, host, port in SERVICES:
        ok = check_tcp(host, port)
        print(f"[{'PASS' if ok else 'FAIL'}] {name} ({host}:{port})")
        if not ok:
            failures += 1

    api_ok = check_api("http://127.0.0.1:8000/api/v1/health")
    print(f"[{'PASS' if api_ok else 'FAIL'}] CipherPost API (http://127.0.0.1:8000/api/v1/health)")
    if not api_ok:
        failures += 1

    if failures:
        print(f"\n{failures} check(s) FAILED.")
        return 1
    print("\nAll smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
