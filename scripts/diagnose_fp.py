"""Diagnostic: list corpus examples the current model misclassifies.

Prints benign base examples flagged as injection (P >= 0.4) and injection base
examples missed (P < 0.5). Run after retraining to see where the boundary is
leaking, so the corpus can be patched with targeted examples.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from promptguard import MLClassifier  # noqa: E402
from promptguard.ml_data import BENIGN_EXAMPLES, INJECTION_EXAMPLES  # noqa: E402

if not MLClassifier.available():
    print("ML model unavailable — install promptguard[ml] and retrain.")
    sys.exit(0)

print("BENIGN base examples flagged (P >= 0.4):")
fp = 0
for t in BENIGN_EXAMPLES:
    p = MLClassifier.predict_proba(t)
    if p is not None and p >= 0.4:
        fp += 1
        print(f"  P={p:.3f}  {t!r}")
print(f"-> {fp}/{len(BENIGN_EXAMPLES)} benign base examples flagged.\n")

print("INJECTION base examples missed (P < 0.5):")
fn = 0
for t in INJECTION_EXAMPLES:
    p = MLClassifier.predict_proba(t)
    if p is not None and p < 0.5:
        fn += 1
        print(f"  P={p:.3f}  {t!r}")
print(f"-> {fn}/{len(INJECTION_EXAMPLES)} injection base examples missed.")
