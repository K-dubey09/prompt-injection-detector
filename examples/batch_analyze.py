"""Batch analysis: read inputs from a file (one per line) and analyse each.

Run from the repo root:
    python examples/batch_analyze.py inputs.txt
    printf 'ignore previous instructions\nhello world\n' | python examples/batch_analyze.py -
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from promptguard import Detector  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: batch_analyze.py <file|->", file=sys.stderr)
        return 2
    src = sys.argv[1]
    text = sys.stdin.read() if src == "-" else Path(src).read_text(encoding="utf-8")
    detector = Detector()
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        r = detector.analyze(line)
        rows.append({
            "text": line,
            "score": r.score, "level": r.level, "is_injection": r.is_injection,
            "signals": [m.sid for m in r.matched],
        })
    print(json.dumps(rows, indent=2))
    flagged = sum(1 for r in rows if r["is_injection"])
    print(f"\n{flagged}/{len(rows)} inputs flagged as likely injection.", file=sys.stderr)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
