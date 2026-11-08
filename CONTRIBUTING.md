# Contributing to PromptGuard

Thanks for considering a contribution. PromptGuard is small on purpose — it's meant to be readable end-to-end — so changes that keep it readable are preferred over changes that make it powerful-but-opaque.

## Setting up

```bash
git clone https://github.com/K-dubey09/prompt-injection-detector.git
cd prompt-injection-detector
pip install -e ".[api,ml,dev]"
```

## Running the tests

There are five suites; please keep all of them green:

```bash
python tests/test_detector.py    # heuristic signals + composite scoring
python tests/test_features.py    # statistical anomaly engine
python tests/test_defense.py     # sanitization + instruction-hierarchy
python tests/test_ml.py          # the trained classifier + integration
python tests/test_api.py         # end-to-end over the FastAPI app
# or: pytest -q
```

## What you might work on

**Add a heuristic signal.** Define a `Signal` in `promptguard/detector.py` (id, name, regex, weight, severity), then add a corpus sample to `tests/corpus.py` that trips it and a test case to `tests/test_detector.py`. Keep weights proportional to severity — the catalogue table in the README should stay accurate.

**Improve the model.** Add labelled examples to `promptguard/ml_data.py` (both injection and benign — benign examples that *borderline-mention* security concepts are the most valuable), then retrain:

```bash
python scripts/train_model.py
```

The script prints accuracy, a classification report, ROC-AUC, a confusion matrix and sanity probes. Commit the regenerated `promptguard/data/classifier.joblib` along with the corpus change so a fresh install gets the new model. Update `MODEL_CARD.md` with the new metrics — it is the honest record of what the model can and can't do.

**Add a defense.** New defenses belong in `promptguard/defense.py`. If it changes the public API, update `schemas.py`, `server.py`, the CLI, and the web UI to match, and add a test. The `--web` / `--api` server modes, the `/screen` + `/screen/batch` endpoints, and the `--cli` REPL live in `server.py` + `schemas.py` + `repl.py`.

## Pull requests

- Keep one logical change per PR.
- Add or update tests for any behaviour change.
- Run `ruff check .` before opening the PR (config lives in `pyproject.toml`); CI does not yet enforce it, but please don't introduce new lint noise.
- Run all five suites before opening the PR — CI runs the same five on Python 3.10–3.13.
- Don't bump the version in a feature PR; that's done at release time.

## Reporting a security vulnerability

A prompt PromptGuard *misses* is a detection bug — see "Reporting a bypass" below, and open a normal issue. A vulnerability *in PromptGuard itself* (for example a way `sanitize` or `build_defense` mishandles input such that a caller relying on it is left exposed) is a security issue: please follow [SECURITY.md](SECURITY.md) instead of a public issue.

## Reporting a bypass

If you find an injection string that PromptGuard misses, that's a useful bug report, not an attack — please open an issue with the input, the score it got, and what it should have been. Misses are exactly what the corpus needs to grow on.
