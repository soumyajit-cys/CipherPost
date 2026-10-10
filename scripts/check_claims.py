"""CI check: fail if README/docs contain banned overstatement phrases.

Banned (case-insensitive):
  production-ready, battle-tested, enterprise-grade

"100%" is flagged only when it looks like an accuracy claim (same line
mentions precision/recall/accuracy/P-R) AND the line is not qualified
with synthetic/lab wording AND the file is not explicitly allow-listed
below with a justification.

Allow-list: file substring -> justification. Listed files may contain
qualified "100%" accuracy statements (synthetic-corpus or lab-only with
basis stated); unqualified production accuracy claims still fail.
Run: python scripts/check_claims.py (exit 1 on violation).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HARD_BANNED = ["production-ready", "battle-tested", "enterprise-grade"]

ALLOWED_100 = {
    "README.md": "Stage 3 100% P/R explicitly synthetic-corpus only + lab basis",
    "docs/pilot-guide.md": "100% P/R explicitly synthetic-corpus only, real-world unknown",
    "docs/design.md": "100% P/R synthetic-corpus pipeline smoke gate",
    "THREAT_MODEL.md": "synthetic 100% explicitly does-not-imply real-world",
    "tests/real/README.md": "synthetic circularity disclaimer (outside docs scan)",
    "docs/evidence/real-eval.md": "lab 1.00 figures with stated 28-capture/94-session basis + limits",
    "docs/ml-evaluation.md": "1.0 on 16 synthetic sessions explicitly smoke-only",
}

ACC_100_RE = re.compile(r"100%")
ACC_CTX_RE = re.compile(r"precision|recall|accuracy|P/R|\bP\b.*\bR\b", re.IGNORECASE)
QUAL_RE = re.compile(r"synthetic|lab", re.IGNORECASE)


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []
    low = text.lower()
    for phrase in HARD_BANNED:
        if phrase in low:
            problems.append(f"{path}: contains banned phrase {phrase!r}")
    if path.suffix == ".md":
        allowed = any(k in str(path) for k in ALLOWED_100)
        for i, line in enumerate(text.splitlines(), 1):
            if ACC_100_RE.search(line) and ACC_CTX_RE.search(line):
                if QUAL_RE.search(line):
                    continue
                if allowed:
                    continue
                problems.append(f"{path}:{i}: unqualified 100% accuracy claim: {line.strip()[:140]}")
    return problems


def main() -> int:
    roots = [ROOT / "README.md", ROOT / "docs", ROOT / "CHANGELOG.md",
             ROOT / "THREAT_MODEL.md"]
    files: list[Path] = []
    for r in roots:
        if r.is_file():
            files.append(r)
        elif r.is_dir():
            files.extend(sorted(r.rglob("*.md")))
    problems: list[str] = []
    for f in files:
        problems.extend(check_file(f))
    seen = list(dict.fromkeys(problems))
    if seen:
        print("claims-check FAILED:")
        for p in seen:
            print(f"  - {p}")
        return 1
    print(f"claims-check OK ({len(files)} markdown files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
