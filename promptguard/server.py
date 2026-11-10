"""
promptguard.server
==================

FastAPI application exposing the PromptGuard detection & defense API and
serving the bundled web UI.

Launch it from the CLI:

    promptguard --web --port 8000        # web UI + API (dev/demo)
    promptguard --api --workers 4        # production API service (scales)

Attaching it as a security layer to another AI service
-------------------------------------------------------
Call ``POST /screen`` with ``{"text": ...}`` before forwarding user input to
your LLM for a single verdict, or ``POST /screen/batch`` with
``{"texts": [...]}`` to screen many inputs in one request. Both return an
``action`` of ``allow`` / ``sanitize`` / ``block``.

Endpoints
---------
- ``GET  /``              -> the web UI (``web/index.html``)
- ``GET  /health``        -> service health & version
- ``POST /analyze``       -> full detection result for one input
- ``POST /analyze/batch`` -> full detection result for many inputs
- ``POST /screen``        -> one-call integration verdict (allow/block/sanitize)
- ``POST /screen/batch``  -> one-call integration verdict for many inputs
- ``POST /sanitize``      -> strip attacker-controlled tokens from text
- ``POST /defend``        -> build an instruction-hierarchy-hardened prompt
- ``GET  /docs``          -> interactive OpenAPI docs (auto-generated)

Static assets (``style.css``, ``app.js``) sit next to ``index.html`` in
``web/`` and are served at the root, so the HTML uses relative paths and
renders correctly whether opened directly or through the server.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import Detector, __version__
from .defense import build_defense, sanitize
from .schemas import (
    AnalyzeBatchRequest,
    AnalyzeBatchResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    DefendRequest,
    DefendResponse,
    HealthResponse,
    MatchModel,
    SanitizeRequest,
    SanitizeResponse,
    ScreenBatchRequest,
    ScreenBatchResponse,
    ScreenResponse,
)

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(
    title="PromptGuard",
    version=__version__,
    description=(
        "A transparent prompt-injection detection & defense toolkit for LLMs. "
        "Combines 13 heuristic signals with a statistical anomaly scorer, a "
        "trained scikit-learn classifier, and active defenses (sanitization + "
        "instruction-hierarchy wrapping). Use POST /screen (single) or "
        "/screen/batch (many) as a one-call screening verdict before "
        "forwarding input to your LLM."
    ),
)

# Permissive CORS so the UI (or any client) can call the API from anywhere.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

def _analyze_to_response(r) -> AnalyzeResponse:
    return AnalyzeResponse(
        score=r.score,
        level=r.level,
        is_injection=r.is_injection,
        input_length=r.input_length,
        heuristic_score=r.heuristic_score,
        stat_anomaly_score=r.stat_anomaly_score,
        ml_score=r.ml_score,
        ml_available=r.ml_available,
        attack_types=r.attack_types,
        matched=[
            MatchModel(sid=m.sid, name=m.name, severity=m.severity,
                       weight=m.weight, snippet=m.snippet)
            for m in r.matched
        ],
        features=r.features,
    )


def _screen_one(det: Detector, text: str) -> ScreenResponse:
    """Build a one-call integration verdict from a detector result."""
    r = det.analyze(text)
    sids = ", ".join(m.sid for m in r.matched[:3]) or "statistical anomaly"
    reason = f"{len(r.matched)} signal(s): {sids}" if r.matched else f"score {r.score}"

    if not r.is_injection:
        return ScreenResponse(
            action="allow", score=r.score, level=r.level,
            reason=f"below threshold (score {r.score})",
        )

    res = sanitize(text)
    if res.actions:
        return ScreenResponse(
            action="sanitize", score=r.score, level=r.level,
            reason=reason, sanitized=res.sanitized,
        )
    return ScreenResponse(action="block", score=r.score, level=r.level, reason=reason)


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@app.post("/analyze", response_model=AnalyzeResponse, tags=["detection"])
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Detect prompt injection (heuristics + statistical + trained ML classifier)."""
    return _analyze_to_response(Detector().analyze(req.text))


@app.post("/analyze/batch", response_model=AnalyzeBatchResponse, tags=["detection"])
def analyze_batch(req: AnalyzeBatchRequest) -> AnalyzeBatchResponse:
    """Analyse many inputs in one request.

    For high-throughput integration. One ``Detector`` is reused across the
    list (the trained model loads once), so a batch is cheaper than N single
    calls. Scale across cores with ``promptguard --api --workers N``.
    """
    det = Detector()
    results: List[AnalyzeResponse] = [_analyze_to_response(det.analyze(t)) for t in req.texts]
    return AnalyzeBatchResponse(results=results)


@app.post("/screen", response_model=ScreenResponse, tags=["detection"])
def screen(req: AnalyzeRequest) -> ScreenResponse:
    """One-call screening verdict for integration with other AI services."""
    return _screen_one(Detector(), req.text)


@app.post("/screen/batch", response_model=ScreenBatchResponse, tags=["detection"])
def screen_batch(req: ScreenBatchRequest) -> ScreenBatchResponse:
    """Screen many inputs in one call.

    The batch endpoint is what lets the service serve at scale: one request
    screens a list of user inputs and returns one verdict per item, so a busy
    gateway can screen a queue of messages without a round-trip per item.
    Scale across cores with ``promptguard --api --workers N``.
    """
    det = Detector()
    results: List[ScreenResponse] = [_screen_one(det, t) for t in req.texts]
    return ScreenBatchResponse(results=results)


@app.post("/sanitize", response_model=SanitizeResponse, tags=["defense"])
def sanitize_endpoint(req: SanitizeRequest) -> SanitizeResponse:
    """Strip attacker-controlled tokens (control tokens, base64 blobs, escapes)."""
    res = sanitize(
        req.text,
        strip_control_tokens=req.strip_control_tokens,
        neutralize_unicode_escapes=req.neutralize_unicode_escapes,
        redact_base64=req.redact_base64,
    )
    return SanitizeResponse(
        original=res.original, sanitized=res.sanitized, actions=res.actions,
    )


@app.post("/defend", response_model=DefendResponse, tags=["defense"])
def defend_endpoint(req: DefendRequest) -> DefendResponse:
    """Build a prompt hardened with the instruction-hierarchy defense."""
    res = build_defense(req.system_prompt, req.user_input,
                        sanitize_input=req.sanitize_input)
    return DefendResponse(prompt=res.prompt, notes=res.notes)


# Serve the web UI at the root LAST, so the API routes above take priority.
# html=True serves index.html for GET "/" ; sibling assets (style.css, app.js)
# are served at their own paths so the HTML can reference them relatively.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
