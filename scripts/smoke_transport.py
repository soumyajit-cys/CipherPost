"""Optional LIVE smoke test for MTA-STS/DANE (requires internet + DNS).

NOT run in CI. Usage:
  PYTHONPATH=backend CIPHERPOST_DNS_RESOLVER=8.8.8.8 python scripts/smoke_transport.py gmail.com

Prints the transport-security posture using real DNS. Results depend on live
infrastructure and are informational only — never committed as labels.
"""
from __future__ import annotations

import json
import sys


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    domain = argv[0] if argv else "gmail.com"
    sys.path.insert(0, "backend")
    from app.proactive.mta_sts import check_domain
    print(json.dumps(check_domain(domain, refresh=True), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
