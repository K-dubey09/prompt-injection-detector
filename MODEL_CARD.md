# Model Card — PromptGuard Injection Classifier

This is the model card for the trained classifier shipped inside PromptGuard
(`promptguard/data/classifier.joblib`). It follows the model-card convention
(Mitchell et al., 2019): what the model is, what it was trained on, how it
performs, and where it breaks. Read it alongside the README's "What this is
not" section.

## Model details

| | |
|---|---|
| **Name** | PromptGuard injection classifier |
| **Version** | 0.5.1 |
| **Trained** | 2026-11-08 |
| **Type** | TF-IDF (char 3–5 + word 1–2 n-grams, sublinear TF) → LogisticRegression |
| **Parameters** | ~8,500 TF-IDF features; `class_weight="balanced"`, `C=2.0`, `liblinear` solver |
| **Artifact** | `promptguard/data/classifier.joblib` (~85 KB, committed to the repo) |
| **Runtime** | scikit-learn ≥ 1.3 (trained on 1.9.1); loaded lazily, falls back to heuristics if absent |
| **License** | MIT |

## Intended use

**Primary:** the third detection layer inside PromptGuard, folded into the
composite `max(heuristic, statistical, ml)` score. It exists to catch
injections that the heuristic rules miss because the phrasing is novel, and —
just as importantly — to *avoid* flagging benign text that merely mentions
"system prompt", "api key", "act as", or "ignore instructions" in a question
or explanation.

**Also suitable for:** a first-pass screening signal in an LLM application's
input pipeline, exposed through the `POST /screen` endpoint.

**Out of scope:** a standalone production classifier. It is a small,
transparent baseline trained on a hand-curated corpus, not a model trained on
millions of real attack attempts. Do not use it as the sole control for a
high-stakes deployment.

## Training data

A hand-curated corpus in `promptguard/ml_data.py`:

- **120** base injection examples across seven categories: direct instruction
  override, persona/jailbreak, prompt leaking, control/role-token injection,
  obfuscation/encoding, data exfiltration, and indirect (retrieved-content)
  injection.
- **104** base benign examples, deliberately seeded with *borderline* phrasing
  — benign role-play, security questions, short task commands ("Summarise this."),
  declarative security advisories that mention system prompts or api keys, and
  document text that mentions secrets or admin accounts — so the model learns
  context, not keywords.

`build_dataset()` augments these (casing variants; benign-wrapped
indirect-injection framing) to **547 samples** (339 injection, 208 benign).
This is the model's biggest limitation: it is small and hand-authored, so it
generalises within the patterns a human thought to write down and only
somewhat beyond them.

## Evaluation

Held-out test set — stratified 80/20 split, `random_state=42`, n_test=110:

| metric | value |
|---|---|
| accuracy | 1.000 |
| ROC-AUC | 1.000 |
| precision (injection) | 1.000 |
| recall (injection) | 1.000 |
| F1 (injection) | 1.000 |
| false-positive rate (benign flagged) | 0.000 |
| false-negative rate (injection missed) | 0.000 |

Confusion matrix: TN=42, FP=0, FN=0, TP=68.

**5-fold cross-validation** on the full corpus: **accuracy 0.985 ± 0.014**
(folds: 0.982, 1.000, 0.963, 1.000, 0.982).

### How to read these numbers honestly

The held-out score is perfect on this corpus — which now includes the
short-prompt and declarative-advisory cases that an earlier version of the
model misclassified (e.g. "Summarise this article." and "Never commit your api
key to a public repository."). The 5-fold CV — **0.985**, with one fold at
0.963 — is the more realistic estimate of how the model behaves on data drawn
from the same distribution. On genuinely novel real-world attacks (new
personae, new obfuscation, multi-step indirect injections) performance will be
lower. Treat the held-out 1.000 as "the model has learned its own training
data", not as a field-accuracy claim.

## Limitations

- **Corpus size.** ~550 augmented examples, hand-written. A real attack that
  uses phrasing the author did not anticipate will be missed.
- **English only.** Non-English and code-mixed inputs are under-represented.
- **Single model family.** TF-IDF + logistic regression is fast and
  explainable but cannot model long-range context the way a transformer can.
- **Obfuscation arms race.** The corpus includes base64 / hex / unicode-escape
  / leet variants, but a determined attacker will find encodings the features
  don't normalise.
- **No real traffic in the benign class.** The benign set is curated, so the
  false-positive rate on actual application traffic is not measured here.
- **Probabilities are not calibrated.** `predict_proba` returns uncalibrated
  scores; the composite thresholds (40 / 70) are deliberately coarse.

## Ethical considerations

PromptGuard is defensive. It does not generate attacks, trains on no private
user data, and the corpus contains only synthetic, self-authored examples. A
false negative means a possible injection reaches the model — mitigated by
combining with heuristics, the active defenses, output filtering, and human
review. A false positive means a benign input is delayed or sanitised — the
less harmful failure mode, and the one the borderline-benign corpus is built
to minimise.

## Reproducing

```bash
pip install -e ".[ml]"
python scripts/train_model.py
```

The script prints the full report above and overwrites
`promptguard/data/classifier.joblib`. The metrics and metadata are also
persisted in the artifact's `meta` block, so the runtime can report what it
is running:

```python
from promptguard import MLClassifier
print(MLClassifier.meta())
# {'kind': 'tfidf-char-word + logistic-regression', 'n_train': 405,
#  'test_metrics': {...}, 'cv_5fold': {'accuracy_mean': 0.988, ...},
#  'sklearn_version': '1.9.1', 'trained_date': '2026-11-08', ...}
```
