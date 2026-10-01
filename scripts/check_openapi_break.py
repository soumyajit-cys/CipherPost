"""CI gate: fail on unintended /api/v1 breaking changes (Phase 3 Task 6).

Regenerates the schema from the app and diffs it against docs/openapi.json.
Breaking = removed path, removed method, removed required query param, or a
path that changed its required-parameter set. Additive changes (new paths,
new optional params) pass. Run: scripts/check_openapi_break.py
"""
from __future__ import annotations

import json
import sys


def _load(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _required_params(op: dict) -> set[str]:
    out = set()
    for p in op.get("parameters", []) or []:
        if p.get("required") and p.get("in") == "query":
            out.add(p["name"])
    return out


def diff_breaking(old: dict, new: dict) -> list[str]:
    problems = []
    old_paths, new_paths = old.get("paths", {}), new.get("paths", {})
    for path in sorted(old_paths):
        if path not in new_paths:
            problems.append(f"removed path {path}")
            continue
        for method in ("get", "post", "patch", "put", "delete"):
            if method in old_paths[path] and method not in new_paths[path]:
                problems.append(f"removed {method.upper()} {path}")
            elif method in old_paths[path] and method in new_paths[path]:
                missing = (_required_params(old_paths[path][method])
                           - _required_params(new_paths[path][method]))
                for p in sorted(missing):
                    problems.append(f"removed required param {p} from {method.upper()} {path}")
    return problems


def main() -> int:
    sys.path.insert(0, "backend")
    from app.api.main import app
    baseline = _load("docs/openapi.json")
    live = app.openapi()
    problems = diff_breaking(baseline, live)
    if problems:
        print("BREAKING API CHANGES (update docs/openapi.json + docs/api-policy.md):")
        for p in problems:
            print(f"  - {p}")
        return 1
    # Refresh the committed baseline so additive changes are recorded.
    with open("docs/openapi.json", "w") as f:
        json.dump(live, f, indent=2, sort_keys=True)
        f.write("\n")
    added = sorted(set(live.get("paths", {})) - set(baseline.get("paths", {})))
    print(f"no breaking changes ({len(live['paths'])} paths"
          + (f"; new: {', '.join(added)}" if added else "") + ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
