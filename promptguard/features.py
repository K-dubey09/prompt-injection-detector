"""
promptguard.features
====================

Statistical feature extraction for prompt-injection detection.

These features *complement* the rule-based signals in :mod:`promptguard.detector`:
they catch *anomalous* inputs — high-entropy blobs, embedded base64 payloads,
control characters, unicode-escape obfuscation, pathological repetition — that
may evade keyword rules. Pure standard library.

The :func:`anomaly_score` function folds the features into a 0-100 anomaly
score, used by the detector alongside the heuristic score.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Dict

# Long runs of base64-charset characters (≥ 40) — likely a hidden payload.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# \uXXXX escape sequences (used to hide keywords from naive filters).
_UNICODE_ESC = re.compile(r"\\u[0-9a-fA-F]{4}")
# C0 control characters except the common whitespace ones (\t \n \r).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Punctuation (ASCII).
_PUNCT_RE = re.compile(r"[!-/:-@\[-`{-~]")
# Zero-width / format characters used to hide keywords inside otherwise-normal
# words (e.g. "igno\u200bre"). U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ),
# U+2060 (WJ), U+FEFF (BOM/ZWNBSP). Invisible in every renderer.
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def _mixed_script_ratio(text: str) -> float:
    """Fraction of letter chars that belong to a Latin-lookalike script
    (Cyrillic or Greek) WHEN the text also contains Latin letters.

    Monolingual text — whether all-Latin English/Spanish/French or all-Cyrillic
    Russian or all-Devanagari Hindi — returns 0, because there is no script
    *mix*. A homoglyph attack like ``іgnorе аll рrevіous`` (Cyrillic і, е, а, р
    smuggled among Latin letters) returns a positive ratio. This is the safe,
    targeted obfuscation signal: it fires on script mixing, not on non-English
    text, so legitimate multilingual prompts do not false-positive.
    """
    latin = cyrillic_greek = 0
    for ch in text:
        cp = ord(ch)
        if ch.isalpha():
            if (0x0041 <= cp <= 0x024F):          # Latin (incl. extended)
                latin += 1
            elif (0x0370 <= cp <= 0x03FF or       # Greek
                  0x0400 <= cp <= 0x04FF):         # Cyrillic
                cyrillic_greek += 1
    total = latin + cyrillic_greek
    if latin == 0 or cyrillic_greek == 0:
        return 0.0
    return cyrillic_greek / total


@dataclass
class Features:
    """Statistical snapshot of one input string."""

    length: int
    word_count: int
    entropy: float              # Shannon entropy over characters (bits)
    uppercase_ratio: float      # uppercase letters / length
    digit_ratio: float          # digits / length
    punctuation_ratio: float    # ASCII punctuation / length
    control_ratio: float        # C0 control chars (excl. \t\n\r) / length
    base64_density: float       # fraction of chars inside ≥40-char base64 runs
    unicode_escape_density: float  # \uXXXX count / length
    max_run_ratio: float        # longest run of an identical char / length
    mixed_script_ratio: float   # Cyrillic/Greek letters among Latin (homoglyphs)
    zero_width_density: float   # invisible format chars (ZWSP/ZWNJ/ZWJ/BOM) / len

    def as_dict(self) -> Dict[str, float]:
        return {k: (v if isinstance(v, (int, float)) else float(v))
                for k, v in asdict(self).items()}


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    h = 0.0
    for count in freq.values():
        p = count / n
        h -= p * math.log2(p)
    return h


def _longest_run_ratio(text: str) -> float:
    if not text:
        return 0.0
    longest = run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            run += 1
            if run > longest:
                longest = run
        else:
            run = 1
    return longest / len(text)


def extract(text: str) -> Features:
    """Compute the statistical feature vector for ``text``."""
    if not isinstance(text, str):
        raise TypeError("extract() expects a str")
    if not text:
        return Features(0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    n = len(text)
    upper = sum(1 for c in text if c.isupper())
    digit = sum(1 for c in text if c.isdigit())
    punct = len(_PUNCT_RE.findall(text))
    control = len(_CONTROL_RE.findall(text))

    b64_chars = sum(len(m.group(0)) for m in _BASE64_RUN.finditer(text))
    base64_density = b64_chars / n

    uesc = len(_UNICODE_ESC.findall(text))
    unicode_escape_density = uesc / n

    zw = len(_ZERO_WIDTH_RE.findall(text))
    zero_width_density = zw / n

    return Features(
        length=n,
        word_count=len(text.split()),
        entropy=round(_shannon_entropy(text), 4),
        uppercase_ratio=round(upper / n, 4),
        digit_ratio=round(digit / n, 4),
        punctuation_ratio=round(punct / n, 4),
        control_ratio=round(control / n, 4),
        base64_density=round(base64_density, 4),
        unicode_escape_density=round(unicode_escape_density, 4),
        max_run_ratio=round(_longest_run_ratio(text), 4),
        mixed_script_ratio=round(_mixed_script_ratio(text), 4),
        zero_width_density=round(zero_width_density, 4),
    )


def anomaly_score(features: Features) -> int:
    """
    Fold the statistical features into a 0-100 anomaly score.

    Calibrated so ordinary English prose scores low (< 20) while encoded /
    obfuscated / control-character-heavy inputs score high (≥ 40). Each
    contributor is independent and explainable.
    """
    score = 0.0

    # High entropy suggests random/encoded data (e.g. base64, hex, ciphertext).
    # Ordinary English is ~3.5-4.0 bits/char; base64 is ~4.5-5.0; pure random ~6.6.
    if features.entropy > 3.8:
        score += min((features.entropy - 3.8) * 25.0, 30.0)

    # Base64 payload density — a strong obfuscation signal.
    score += features.base64_density * 50.0

    # Raw control characters (rare in legitimate prompts).
    score += min(features.control_ratio * 100.0, 30.0)

    # \uXXXX escape obfuscation.
    score += min(features.unicode_escape_density * 200.0, 25.0)

    # Pathological single-character repetition (e.g. "AAAA...").
    if features.max_run_ratio > 0.3:
        score += 10.0

    # v0.5.4: mixed-script homoglyphs (Cyrillic/Greek letters smuggled among
    # Latin to disguise keywords like "іgnorе"). Safe vs non-English text —
    # monolingual text never mixes scripts, so this only fires on the attack.
    if features.mixed_script_ratio > 0:
        score += min(features.mixed_script_ratio * 200.0, 25.0)

    # v0.5.4: zero-width / format characters (ZWSP, ZWNJ, ZWJ, BOM) used to
    # break keywords invisibly ("igno\u200bre"). Rare in legitimate input, so
    # even a small density is suspicious.
    if features.zero_width_density > 0:
        score += min(features.zero_width_density * 500.0, 20.0)

    return int(round(min(score, 100.0)))
