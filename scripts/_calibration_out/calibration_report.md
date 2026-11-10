# PromptGuard threshold calibration (v0.5.3)

Calibrated on the **validation** partition (`64`) — max-margin midpoint of validation separating range [44, 83] (0-FP & 0-FN on validation).

- Validation n=62; benign composite 0–43, malicious composite 83–100, gap=40.

- Test n=62; evaluated ONCE at the calibrated threshold. Per-layer confusion (threshold=64):

| layer | TN | FP | FN | TP | precision | recall | f1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|
| heuristic | 24 | 0 | 35 | 3 | 1.000 | 0.079 | 0.146 | 0.000 | 0.921 |
| stat | 24 | 0 | 38 | 0 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 |
| ml | 24 | 0 | 0 | 38 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| composite | 24 | 0 | 0 | 38 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

## Reproduce

```
python scripts/build_evaluation_dataset.py   # rebuild CSV
python scripts/train_model.py                # retrain
python scripts/calibrate_and_evaluate.py     # this report
# user's tooling on the scored validation export:
python scripts/calibrate_threshold.py scripts/_calibration_out/scored_validation.csv --min-threshold 0 --max-threshold 100 --step 1
```
