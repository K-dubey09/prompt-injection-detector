"""
promptguard.schemas
===================

Pydantic v2 request/response models for the PromptGuard HTTP API.

This module depends on ``pydantic`` (installed via the ``api`` extra:
``pip install promptguard[api]``). The core detector / features / defense
modules remain zero-dependency; the trained classifier needs the ``ml`` extra.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class MatchModel(BaseModel):
    """A single heuristic signal that fired."""

    sid: str = Field(..., description="Stable signal id, e.g. 'INJ-01'")
    name: str
    severity: str = Field(..., description="low | medium | high | critical")
    weight: int
    snippet: str = Field(..., description="The matched substring (truncated)")


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=0, max_length=100_000,
                      description="The user-supplied text to analyse")


class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Composite risk score 0-100")
    level: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    is_injection: bool = Field(..., description="True if score >= INJECTION_THRESHOLD (52)")
    input_length: int
    heuristic_score: int = Field(..., ge=0, le=100)
    stat_anomaly_score: int = Field(..., ge=0, le=100)
    ml_score: int = Field(..., ge=0, le=100, description="Trained-classifier score (calibrated); 0 if model unavailable")
    ml_available: bool = Field(..., description="Whether the ML model was used")
    attack_types: List[str] = Field(
        default_factory=list,
        description="High-level attack families that fired (instruction_override, "
                    "jailbreak_persona, prompt_extraction, control_token_injection, "
                    "obfuscation_encoding, data_exfiltration) — a Llama-Guard-style "
                    "coded verdict rolled up from the matched signals")
    matched: List[MatchModel] = Field(default_factory=list)
    features: Dict[str, float] = Field(default_factory=dict)


class AnalyzeBatchRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=1000,
                             description="Inputs to analyse (1-1000 per request)")


class AnalyzeBatchResponse(BaseModel):
    results: List[AnalyzeResponse]


class SanitizeRequest(BaseModel):
    text: str = Field(..., min_length=0, max_length=100_000)
    redact_base64: bool = True
    neutralize_unicode_escapes: bool = True
    strip_control_tokens: bool = True


class SanitizeResponse(BaseModel):
    original: str
    sanitized: str
    actions: List[str] = Field(default_factory=list)


class DefendRequest(BaseModel):
    system_prompt: str = Field(..., description="The legitimate system instruction")
    user_input: str = Field(..., description="Untrusted user-supplied content")
    sanitize_input: bool = True


class DefendResponse(BaseModel):
    prompt: str = Field(..., description="The hardened prompt to send to the LLM")
    notes: List[str] = Field(default_factory=list)


class ScreenResponse(BaseModel):
    """One-call integration verdict from ``POST /screen``.

    Callers that just want a decision before forwarding input to their LLM
    should use ``/screen`` (or ``/screen/batch``) instead of interpreting the
    full ``/analyze`` reply.
    """

    action: str = Field(..., description="allow | block | sanitize")
    score: int = Field(..., ge=0, le=100, description="Composite risk score 0-100")
    level: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    reason: str = Field(..., description="Short human-readable reason for the action")
    sanitized: Optional[str] = Field(
        None, description="Present when action == 'sanitize': the cleaned text to forward"
    )


class ScreenBatchRequest(BaseModel):
    texts: List[str] = Field(..., min_length=1, max_length=1000,
                             description="Inputs to screen (1-1000 per request)")


class ScreenBatchResponse(BaseModel):
    results: List[ScreenResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
