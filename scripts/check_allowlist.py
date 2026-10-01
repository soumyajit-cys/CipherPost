"""CI check: every audit allowlist entry needs id + justification + unexpired date.

Stdlib only (no yaml dependency): parses the fixed `.audit-allowlist.yml`
schema of `tool:` sections containing `- id:` entries.
"""
from __future__ import annotations

import datetime
import re
import sys


def parse_allowlist(path: str) -> dict[str, list[dict]]:
    tools: dict[str, list[dict]] = {}
    current_tool: str | None = None
    current: dict | None = None
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_-]+):\s*(\[\])?\s*$", stripped)
            if m and not line.startswith((" ", "\t")):
                current_tool = m.group(1)
                tools.setdefault(current_tool, [])
                current = None
                continue
            m = re.match(r"^-\s*id:\s*(.+)$", stripped)
            if m and current_tool:
                current = {"id": m.group(1).strip()}
                tools[current_tool].append(current)
                continue
            m = re.match(r"^(justification|expires):\s*(.+)$", stripped)
            if m and current is not None:
                current[m.group(1)] = m.group(2).strip().strip('"')
    return tools


def main() -> int:
    tools = parse_allowlist(".audit-allowlist.yml")
    problems: list[str] = []
    today = datetime.date.today().isoformat()
    for tool in ("pip", "npm", "secrets"):
        for i, e in enumerate(tools.get(tool, [])):
            for field in ("id", "justification", "expires"):
                if not str(e.get(field, "")).strip():
                    problems.append(f"{tool}[{i}]: missing {field}")
            if e.get("expires", "") and e["expires"] < today:
                problems.append(f"{tool}[{i}]: expired {e['expires']}")
    if problems:
        print("allowlist problems:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("allowlist ok (no unjustified ignores)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
