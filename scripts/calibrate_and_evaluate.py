"""Calibrate the PromptGuard threshold on the CSV validation split and
evaluate once on the untouched test split.

Pipeline (evidence-based, per the starter README):
  1. Score the CSV *validation* partition with the full detector (composite +
     heuristic + stat + ml). Write ``scored_validation.csv`` with columns
     ``y_true, score`` (plus per-layer columns) so the user's
     ``calibrate_threshold.py`` can consume it directly.
  2. Sweep thresholds on validation composite scores; pick the threshold that
     yields 0 false positives AND 0 false negatives if a clean separator
     exists, otherwise the best-F1 threshold with FPR=0 preferred.
  3. Evaluate ONCE on the *test* partition at the calibrated threshold:
     confusion matrix + precision/recall/F1/FPR/FNR for each layer
     (heuristic, stat, ml, composite) independently, exactly as the README
     requires ("keep heuristic, statistical and ML outputs separately logged;
     evaluate each layer and the combined decision policy independently").
  4. Write a JSON + Markdown calibration report.

Run:  python scripts/calibrate_and_evaluate.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from promptguard.detector import Detector  # noqa: E402
from promptguard.ml_data import EVALUATION_CSV  # noqa: E402

OUT_DIR = REPO / "scripts" / "_calibration_out"
SCORED_VAL_CSV = OUT_DIR / "scored_validation.csv"
SCORED_TEST_CSV = OUT_DIR / "scored_test.csv"
SWEEP_CSV = OUT_DIR / "threshold_sweep_validation.csv"
REPORT_JSON = OUT_DIR / "calibration_report.json"
REPORT_MD = OUT_DIR / "calibration_report.md"


def _load_split(split: str) -> list[dict]:
    rows = []
    with open(EVALUATION_CSV, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["split"] == split:
                rows.append(r)
    return rows


def _score(rows: list[dict], det: Detector) -> list[dict]:
    out = []
    for r in rows:
        res = det.analyze(r["text"])
        out.append({
            "example_id": r["example_id"],
            "y_true": 1 if r["label"] == "malicious" else 0,
            "label": r["label"],
            "category": r["category"],
            "text": r["text"],
            "heuristic": res.heuristic_score,
            "stat": res.stat_anomaly_score,
            "ml": res.ml_score,
            "score": res.score,  # composite = max(heuristic, stat, ml)
        })
    return out


def _metrics(y: list[int], pred: list[int]) -> dict:
    tn = fp = fn = tp = 0
    for yi, pi in zip(y, pred):
        if yi == 0 and pi == 0:
            tn += 1
        elif yi == 0 and pi == 1:
            fp += 1
        elif yi == 1 and pi == 0:
            fn += 1
        else:
            tp += 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    bal = 0.5 * (rec + (tn / (tn + fp) if (tn + fp) else 0.0))
    return {"TN": tn, "FP": fp, "FN": fn, "TP": tp,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4),
            "fnr": round(fnr, 4), "balanced_accuracy": round(bal, 4)}


def _sweep(scored: list[dict]) -> list[dict]:
    """Sweep composite thresholds 0..100 step 1 on validation."""
    y = [r["y_true"] for r in scored]
    scores = [r["score"] for r in scored]
    records = []
    # candidate thresholds: 0..100 plus midpoints between consecutive distinct
    # scores, to catch the exact separating boundary.
    cands = sorted(set(range(0, 101)) |
                   {s + 1 for s in scores} | {s - 0.5 for s in scores})
    for t in cands:
        if t < 0:
            continue
        pred = [1 if s >= t else 0 for s in scores]
        m = _metrics(y, pred)
        records.append({"threshold": t, **m})
    return records


def _pick_threshold(sweep: list[dict]) -> tuple[float, str]:
    """Prefer 0-FP-and-0-FN separators. When a clean separator exists, pick the
    MIDPOINT of the separating range (lowest 0-FP threshold .. highest 0-FN
    threshold) — this maximizes the minimum margin to BOTH classes, which is
    the right call for a security tool where a missed attack (FN) costs more
    than a false alarm (FP) but neither should have zero margin. Otherwise fall
    back to best-F1 with FPR=0 preferred, then best-F1 overall."""
    perfect = [r for r in sweep if r["FP"] == 0 and r["FN"] == 0]
    if perfect:
        low = min(r["threshold"] for r in perfect)   # lowest 0-FP cutoff
        high = max(r["threshold"] for r in perfect)  # highest 0-FN cutoff
        mid = round((low + high) / 2)
        return mid, (f"max-margin midpoint of validation separating range "
                     f"[{low}, {high}] (0-FP & 0-FN on validation)")
    fpr0 = [r for r in sweep if r["FP"] == 0]
    if fpr0:
        best = max(fpr0, key=lambda r: (r["f1"], r["recall"], r["threshold"]))
        return best["threshold"], "best-F1 with FPR=0 (recall preferred)"
    best = max(sweep, key=lambda r: (r["f1"], r["balanced_accuracy"]))
    return best["threshold"], "best-F1 overall (FPR>0 tolerated)"


def _write_scored_csv(scored: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        cols = ["example_id", "y_true", "label", "category", "score",
                "heuristic", "stat", "ml", "text"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in scored:
            w.writerow(r)


def _layer_eval(scored: list[dict], threshold: float) -> dict:
    """Per-layer evaluation at a single threshold (each layer scored 0-100)."""
    y = [r["y_true"] for r in scored]
    out = {}
    for layer in ("heuristic", "stat", "ml", "score"):
        pred = [1 if r[layer] >= threshold else 0 for r in scored]
        out[layer] = _metrics(y, pred)
    return out


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    det = Detector()

    val_rows = _load_split("validation")
    test_rows = _load_split("test")
    print(f"validation: {len(val_rows)} rows | test: {len(test_rows)} rows")

    val_scored = _score(val_rows, det)
    test_scored = _score(test_rows, det)

    _write_scored_csv(val_scored, SCORED_VAL_CSV)
    _write_scored_csv(test_scored, SCORED_TEST_CSV)
    print(f"wrote scored validation -> {SCORED_VAL_CSV}")
    print(f"wrote scored test       -> {SCORED_TEST_CSV}")

    # --- threshold sweep on validation composite ---
    sweep = _sweep(val_scored)
    with open(SWEEP_CSV, "w", newline="", encoding="utf-8") as f:
        cols = ["threshold", "TN", "FP", "FN", "TP", "precision", "recall",
                "f1", "fpr", "fnr", "balanced_accuracy"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sorted(sweep, key=lambda x: x["threshold"]):
            w.writerow(r)
    print(f"wrote sweep             -> {SWEEP_CSV}")

    threshold, rationale = _pick_threshold(sweep)
    print(f"\ncalibrated threshold (validation): {threshold}  [{rationale}]")

    # show the validation score gap (benign max vs malicious min composite)
    ben = [r["score"] for r in val_scored if r["y_true"] == 0]
    mal = [r["score"] for r in val_scored if r["y_true"] == 1]
    print(f"validation composite: benign min/max = {min(ben)}/{max(ben)}; "
          f"malicious min/max = {min(mal)}/{max(mal)}")
    print(f"  separation gap (mal_min - ben_max) = {min(mal) - max(ben)}")

    # --- final evaluation ONCE on the test partition ---
    test_layer = _layer_eval(test_scored, threshold)
    print(f"\n--- TEST evaluation @ threshold={threshold} (n={len(test_scored)}) ---")
    print(f"{'layer':12s} {'TN':>3s} {'FP':>3s} {'FN':>3s} {'TP':>3s} "
          f"{'prec':>6s} {'rec':>6s} {'f1':>6s} {'fpr':>6s} {'fnr':>6s}")
    for layer in ("heuristic", "stat", "ml", "score"):
        m = test_layer[layer]
        name = "composite" if layer == "score" else layer
        print(f"{name:12s} {m['TN']:3d} {m['FP']:3d} {m['FN']:3d} {m['TP']:3d} "
              f"{m['precision']:6.3f} {m['recall']:6.3f} {m['f1']:6.3f} "
              f"{m['fpr']:6.3f} {m['fnr']:6.3f}")

    # --- the difficult pairs: show borderline benign + borderline malicious ---
    print("\n--- validation borderline cases (closest to threshold) ---")
    for r in sorted(val_scored, key=lambda x: abs(x["score"] - threshold))[:12]:
        flag = "MAL" if r["y_true"] == 1 else "BEN"
        print(f"  [{flag}] comp={r['score']:3d} h={r['heuristic']:3d} "
              f"s={r['stat']:3d} m={r['ml']:3d} | {r['category']:30s} | "
              f"{r['text'][:60]}")

    # --- report ---
    report = {
        "threshold_calibrated_on": "validation",
        "calibrated_threshold": threshold,
        "threshold_rationale": rationale,
        "validation": {
            "n": len(val_scored),
            "benign_composite_min_max": [min(ben), max(ben)],
            "malicious_composite_min_max": [min(mal), max(mal)],
            "separation_gap": min(mal) - max(ben),
            "composite_metrics_at_threshold": _metrics(
                [r["y_true"] for r in val_scored],
                [1 if r["score"] >= threshold else 0 for r in val_scored]),
        },
        "test": {
            "n": len(test_scored),
            "per_layer_at_threshold": test_layer,
        },
        "artifacts": {
            "scored_validation_csv": str(SCORED_VAL_CSV.relative_to(REPO)),
            "scored_test_csv": str(SCORED_TEST_CSV.relative_to(REPO)),
            "sweep_csv": str(SWEEP_CSV.relative_to(REPO)),
        },
    }
    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nwrote report json -> {REPORT_JSON}")

    # markdown summary
    md = ["# PromptGuard threshold calibration (v0.5.3)\n",
          f"Calibrated on the **validation** partition (`{threshold}`) — "
          f"{rationale}.\n",
          f"- Validation n={len(val_scored)}; benign composite "
          f"{min(ben)}–{max(ben)}, malicious composite {min(mal)}–{max(mal)}, "
          f"gap={min(mal)-max(ben)}.\n",
          f"- Test n={len(test_scored)}; evaluated ONCE at the calibrated "
          f"threshold. Per-layer confusion (threshold={threshold}):\n",
          "| layer | TN | FP | FN | TP | precision | recall | f1 | FPR | FNR |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for layer in ("heuristic", "stat", "ml", "score"):
        m = test_layer[layer]
        name = "composite" if layer == "score" else layer
        md.append(f"| {name} | {m['TN']} | {m['FP']} | {m['FN']} | {m['TP']} | "
                  f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
                  f"{m['fpr']:.3f} | {m['fnr']:.3f} |")
    md.append("\n## Reproduce\n")
    md.append("```")
    md.append("python scripts/build_evaluation_dataset.py   # rebuild CSV")
    md.append("python scripts/train_model.py                # retrain")
    md.append("python scripts/calibrate_and_evaluate.py     # this report")
    md.append("# user's tooling on the scored validation export:")
    md.append("python scripts/calibrate_threshold.py "
              "scripts/_calibration_out/scored_validation.csv "
              "--min-threshold 0 --max-threshold 100 --step 1")
    md.append("```")
    with open(REPORT_MD, "w") as f:
        f.write("\n".join(md) + "\n")
    print(f"wrote report md   -> {REPORT_MD}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
