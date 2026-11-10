#!/usr/bin/env python3
"""
Threshold calibration for PromptGuard score exports.

Input CSV columns:
  y_true : 1 for malicious, 0 for benign
  score  : model score where higher means more malicious

Example:
  python calibrate_threshold.py scored_validation.csv --min-threshold 0 --max-threshold 100 --step 1
"""
import argparse

import pandas as pd
from sklearn.metrics import (
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "balanced_accuracy": balanced_accuracy_score(y, pred),
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("csv")
    p.add_argument("--min-threshold", type=float, default=0)
    p.add_argument("--max-threshold", type=float, default=100)
    p.add_argument("--step", type=float, default=1)
    p.add_argument("--out", default="threshold_sweep.csv")
    args = p.parse_args()

    df = pd.read_csv(args.csv)
    missing = {"y_true", "score"} - set(df.columns)
    if missing:
        raise SystemExit(f"Missing required columns: {sorted(missing)}")
    if df.empty or not set(df["y_true"].dropna().unique()).issubset({0, 1}):
        raise SystemExit("y_true must contain 0/1 labels and the CSV must not be empty.")
    if df[["y_true", "score"]].isna().any().any():
        raise SystemExit("y_true and score cannot contain missing values.")

    records = []
    thresholds = [args.min_threshold + i * args.step
                  for i in range(int((args.max_threshold - args.min_threshold) / args.step) + 1)]
    for threshold in thresholds:
        pred = (df["score"] >= threshold).astype(int)
        records.append({"threshold": threshold, **metrics(df["y_true"].astype(int), pred)})
    result = pd.DataFrame(records).sort_values(
        ["f1", "balanced_accuracy", "false_positive_rate"],
        ascending=[False, False, True]
    )
    result.to_csv(args.out, index=False)
    print(result.head(15).to_string(index=False))
    print(f"\nFull sweep saved to: {args.out}")
    print("Choose threshold on validation data only; report final metrics once on untouched test data.")

if __name__ == "__main__":
    main()
