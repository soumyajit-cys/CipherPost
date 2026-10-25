#!/usr/bin/env python3
"""Smoke test for the CipherPost live-run lab.

Checks that every mail port is listening on 127.0.0.1 and that the
CipherPost API answers on http://127.0.0.1:8000/api/v1/health.

Usage:
    python3 smoke_test.py [--host 127.0.0.1]

Exit codes: 0 all pass, 1 one or more failures.
"""
import argparse
import socket
import sys
import urllib.request

SERVICES = [
    ("SMTP 25 (STARTTLS)", 25),
    ("Submission 587 (STARTTLS)", 587),
    ("SMTPS 465 (implicit TLS)", 465),
    ("IMAP 143 (STARTTLS)", 143),
    ("IMAPS 993 (implicit TLS)", 993),
    ("POP3 110 (STLS)", 110),
    ("POP3S 995 (implicit TLS)", 995),
]
API_PORT = 8000
API_PATH = "/api/v1/health"


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


def main_with_overrides(host: str, ports: list[tuple[str, int]],
                        api_url: str) -> int:
    """Run all checks against explicit targets. Separated from main() so the
    pass/fail logic is unit-testable without a running lab."""
    failures = 0
    for name, port in ports:
        ok = check_tcp(host, port)
        print(f"[{'PASS' if ok else 'FAIL'}] {name} ({host}:{port})")
        if not ok:
            failures += 1

    api_ok = check_api(api_url)
    print(f"[{'PASS' if api_ok else 'FAIL'}] CipherPost API ({api_url})")
    if not api_ok:
        failures += 1

    if failures:
        print(f"\n{failures} check(s) FAILED.")
        return 1
    print("\nAll smoke tests passed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    return main_with_overrides(
        host=args.host,
        ports=list(SERVICES),
        api_url=f"http://{args.host}:{API_PORT}{API_PATH}")


if __name__ == "__main__":
    sys.exit(main())
