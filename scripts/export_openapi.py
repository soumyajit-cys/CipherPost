"""Export the live OpenAPI schema (Phase 3 Task 6).

Usage: PYTHONPATH=backend python scripts/export_openapi.py [out.json]
Compares against docs/openapi.json when --check is passed (CI gate is
scripts/check_openapi_break.py; this script only writes).
"""
from __future__ import annotations

import json
import sys


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    out = argv[0] if argv else "docs/openapi.json"
    sys.path.insert(0, "backend")
    from app.api.main import app
    schema = app.openapi()
    with open(out, "w") as f:
        json.dump(schema, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {out} ({len(schema['paths'])} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
