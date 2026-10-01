"""CI check: every audit allowlist entry needs id + justification + unexpired date."""
from __future__ import annotations

import datetime
import sys


def main() -> int:
    import yaml
    with open(".audit-allowlist.yml") as f:
        data = yaml.safe_load(f) or {}
    problems: list[str] = []
    today = datetime.date.today().isoformat()
    for tool in ("pip", "npm", "secrets"):
        entries = data.get(tool) or []
        if not isinstance(entries, list):
            problems.append(f"{tool}: must be a list")
            continue
        for i, e in enumerate(entries):
            for field in ("id", "justification", "expires"):
                if not (isinstance(e, dict) and str(e.get(field, "")).strip()):
                    problems.append(f"{tool}[{i}]: missing {field}")
            exp = str((e or {}).get("expires", ""))
            if exp and exp < today:
                problems.append(f"{tool}[{i}]: expired {exp}")
    if problems:
        print("allowlist problems:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("allowlist ok (no unjustified ignores)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
