# Changelog

## 0.5.0

Two new ways to run PromptGuard, plus batch screening for serving at scale.

- new: `--cli` / `cli` — an interactive REPL. A persistent session where you
  run `analyze`, `sanitize`, `defend`, and `batch <file>` repeatedly without
  re-invoking the command each time. Sets a reusable system prompt for
  `defend` and toggles JSON output on the fly.
- new: `--api` / `api` — a production HTTP API service for machine-to-machine
  integration. Binds `0.0.0.0` by default and adds `--workers N` (uvicorn
  multi-process) so it serves many concurrent callers across cores. This is
  the mode to run when your AI server connects to PromptGuard as a screening
  service. `--web` remains the dev/demo mode (UI + single worker).
- new: `POST /screen/batch` and `POST /analyze/batch` — check many inputs in
  one request. A batch endpoint is what makes the service scale: one call
  screens a list of user inputs and returns one verdict per item, so a busy
  gateway can screen a queue of messages without a round-trip per item.
- new: `examples/batch_screen.py` — a dependency-free batch integration
  example.
- changed: README rewritten around the run modes (`--cli`, `--web`, `--api`,
  plus the one-shot commands) and the batch endpoints.
- unchanged: the trained model and corpus. `classifier.joblib` is identical to
  0.4.0; see MODEL_CARD.md.

## 0.4.0

Three things users asked for: a web UI that actually loads its CSS/JS, a
multi-command CLI with a `--web` server mode, and a genuinely evaluated,
deploy-ready model with honest documentation.

- fixed: the web UI's CSS/JS now load via relative paths, and the server serves
  the `web/` directory at the root instead of under `/static`. The page renders
  styled out of the box — including when opened directly — and the assets no
  longer depend on a `/static` prefix that didn't always resolve.
- new: multi-command CLI. `promptguard --web` (or `serve`) launches the FastAPI
  web UI + HTTP API, framed as a screening layer other AI services can attach
  to. The `analyze` / `sanitize` / `defend` one-shot commands are unchanged,
  bare text still defaults to `analyze`, and `--version` is supported.
- new: `POST /screen` — a one-call integration verdict (`allow` / `block` /
  `sanitize`) for callers that want a single decision before forwarding input
  to their LLM, instead of interpreting the full `/analyze` response.
- new: `MODEL_CARD.md` — training data, held-out evaluation (accuracy,
  precision/recall/F1, ROC-AUC), 5-fold cross-validation, intended use and
  limitations. Industry-standard model documentation.
- changed: the training corpus grew (~+60 labelled examples: more diverse
  attacks and more borderline-but-benign phrasing). `scripts/train_model.py`
  now reports ROC-AUC, a confusion matrix, and 5-fold CV, and persists the
  metrics + sklearn version + train date in the artifact's `meta`.
- changed: README rewritten around the new commands, the `/screen` integration
  pattern, and the model card.

## 0.3.1

Polish and hardening pass — no change to detection behaviour and no new runtime dependencies. Brings the repo up to the governance and tooling standard expected of a small open-source security library.

- fixed: `detector.py` module docstring was stale (said "two layers" / `max(heuristic, statistical)` / "not a trained ML model") — now describes the actual three-layer engine and the `max(heuristic, statistical, ml)` composite
- new: `SECURITY.md` — vulnerability-disclosure policy (a security tool should have one)
- new: `.github/dependabot.yml` — weekly checks for pip + GitHub Actions
- new: `[tool.ruff]` and `[tool.pytest.ini_options]` config in `pyproject.toml` (lint + test layout, zero runtime cost)
- changed: README install instructions are now honest — install from the GitHub source (`pip install -e \".[extra]\"`) rather than an implied PyPI publish that does not exist yet
- changed: `CONTRIBUTING.md` notes the lint config and points vulnerability reports at `SECURITY.md`
- changed: `project.urls` now lists Issues + Changelog

## 0.3.0

Added a **trained machine-learning classifier** as a third detection layer — the headline change. A TF-IDF vectorizer (character 3–5 + word 1–2 n-grams) feeding a class-balanced logistic regression, trained on a hand-curated ~400-example corpus (`promptguard/ml_data.py`) and shipped as a bundled artifact (`promptguard/data/classifier.joblib`). The composite score is now `max(heuristic, statistical, ml)`; all three are reported. The benign corpus is deliberately seeded with borderline-but-harmless phrasing (benign role-play, security questions, document text) so the model learns context rather than keyword-matching — the thing heuristics alone cannot do.

- new: `promptguard/ml.py` — runtime classifier with graceful fallback if scikit-learn is missing
- new: `promptguard/ml_data.py` — labelled corpus; `scripts/train_model.py` — retraining
- new: `ml` extra (`scikit-learn`, `numpy`, `joblib`); `all` extra for everything
- new: `tests/test_ml.py`; the API, CLI, and web UI now report `ml_score` / `ml_available`
- changed: requires-python `>=3.9` (3.8 is EOL); CI matrix is 3.10–3.13
- fixed: CI test job and docker smoke test (retry loop + log dump on failure)
- changed: README rewritten

## 0.2.0

Grew the single-file heuristic detector into a toolkit with detection *and* defense.

- new: statistical anomaly engine (`features.py`) — entropy, base64 density, control chars, unicode escapes
- new: active defenses (`defense.py`) — `sanitize()` + `build_defense()` instruction-hierarchy wrapping
- new: FastAPI REST API (`/analyze`, `/sanitize`, `/defend`, `/health`) + Pydantic schemas
- new: single-page web UI with an interactive demo
- new: `analyze` / `sanitize` / `defend` CLI subcommands with `--json` / `--file`
- new: Dockerfile, docker-compose, GitHub Actions CI
- changed: composite score `max(heuristic, statistical)`; `api` and `dev` extras

## 0.1.0

Initial release: a transparent, zero-dependency heuristic prompt-injection detector with 13 weighted rules, a CLI, and a labelled test corpus.
