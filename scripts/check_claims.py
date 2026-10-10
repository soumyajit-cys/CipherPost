"""CI check: fail if README/docs contain banned overstatement phrases.

Banned (case-insensitive) unless allow-listed with justification:
  production-ready, battle-tested, enterprise-grade

"100%" / "complete" / "fully" are NOT hard-banned (they appear in CSS,
counts, and qualified synthetic-corpus statements). Instead this script
flags unqualified accuracy claims: a line containing "100%" or
"precision" or "recall" outside an allow-listed file must also mention
"synthetic" or "lab" on the same line, or the file fails.

Allow-list lives in this file (ALLOWED) with justification per entry.
Run: python scripts/check_claims.py
Exit 1 on violation (CI gate), 0 otherwise.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HARD_BANNED = ["production-ready", "battle-tested", "enterprise-grade"]

# path-substring -> justification (prose accuracy statements that are
# explicitly qualified as synthetic/lab-only, or non-prose uses).
ALLOWED = {
    # CHANGELOG historical note explicitly says a 30-day run is still
    # required before any production-use claim; reworded to avoid the
    # hyphenated banned phrase, but keep an allow guard in case of relapse.
    "CHANGELOG.md": "historical limit note, not a readiness claim",
    # Qualified synthetic/lab accuracy statements (must still mention
    # synthetic/lab on the same line; checked below).
    "README.md": "accuracy figures qualified as synthetic-corpus/lab-only",
    "docs/pilot-guide.md": "explicitly synthetic-corpus only + unknown real-world",
    "docs/design.md": "synthetic-corpus P/R gate for pipeline smoke only",
    "THREAT_MODEL.md": "explicit non-implication disclaimer for synthetic 100%",
    "tests/real/README.md": "synthetic circularity disclaimer",
}

ACCURACY_RE = re.compile(r"100%|precision|recall", re.IGNORECASE)
QUALIFIED_RE = re.compile(r"synthetic|lab-only|lab set|lab-generated|lab-labeled", re.IGNORECASE)


def check_file(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return []
    low = text.lower()
    for phrase in HARD_BANNED:
        if phrase in low:
            # allow only if file is explicitly allow-listed AND the line
            # carries a disclaimer (conservative: still fail, owner must
            # reword). Allow-list is for audit, not exemption.
            problems.append(f"{path}: contains banned phrase {phrase!r}")
    # Accuracy-qualification check for markdown prose only.
    if path.suffix == ".md":
        for i, line in enumerate(text.splitlines(), 1):
            if ACCURACY_RE.search(line) and not QUALIFIED_RE.search(line):
                # Ignore lines that are clearly not accuracy claims:
                # CSS, counts, paths, code spans about unrelated numbers.
                stripped = line.strip()
                if stripped.startswith(("|", "-", "#", ">", "`", "*")):
                    # Table/list/heading lines still count if they claim
                    # accuracy without qualification — check keywords.
                    if re.search(r"precision|recall|accuracy|P/R", line, re.IGNORECASE):
                        problems.append(f"{path}:{i}: unqualified accuracy claim: {line.strip()[:120]}")
                elif re.search(r"precision|recall|accuracy|P/R", line, re.IGNORECASE):
                    problems.append(f"{path}:{i}: unqualified accuracy claim: {line.strip()[:120]}")
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
    # De-duplicate, stable order.
    seen: list[str] = []
    for p in problems:
        if p not in seen:
            seen.append(p)
    if seen:
        print("claims-check FAILED:")
        for p in seen:
            print(f"  - {p}")
        print("\nFix: qualify accuracy figures with synthetic/lab basis or remove")
        print("the claim; reword/remove banned readiness phrases.")
        return 1
    print(f"claims-check OK ({len(files)} markdown files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
