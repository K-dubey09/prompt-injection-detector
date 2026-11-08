"""
promptguard.ml
==============

Runtime prompt-injection classifier — a trained, bundled scikit-learn model.

The artifact (TF-IDF vectorizer + LogisticRegression) is shipped at
``promptguard/data/classifier.joblib`` and produced by ``scripts/train_model.py``.
This module loads it lazily and exposes :class:`MLClassifier`.

If scikit-learn / joblib is not installed, or the artifact is missing, the
classifier reports unavailable and the detector silently falls back to
heuristic + statistical scoring. Install the ``ml`` extra to enable it:

    pip install promptguard[ml]
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

_DATA = Path(__file__).resolve().parent / "data" / "classifier.joblib"


class MLClassifier:
    """Lazily-loaded singleton wrapper around the bundled sklearn model."""

    _bundle: Optional[Dict] = None
    _loaded: bool = False

    @classmethod
    def _ensure(cls) -> None:
        if cls._loaded:
            return
        cls._loaded = True
        try:
            import joblib  # type: ignore
            if _DATA.is_file():
                cls._bundle = joblib.load(_DATA)
        except Exception:
            cls._bundle = None

    @classmethod
    def available(cls) -> bool:
        """True if sklearn + joblib are importable and the artifact is present."""
        try:
            import sklearn  # type: ignore  # noqa: F401
        except Exception:
            return False
        cls._ensure()
        return cls._bundle is not None

    @classmethod
    def predict_proba(cls, text: str) -> Optional[float]:
        """Return P(injection) in [0, 1], or None if the model is unavailable."""
        cls._ensure()
        if cls._bundle is None:
            return None
        try:
            vec = cls._bundle["vectorizer"]
            clf = cls._bundle["model"]
            p = float(clf.predict_proba(vec.transform([text]))[0, 1])
            return max(0.0, min(1.0, p))
        except Exception:
            return None

    @classmethod
    def meta(cls) -> Dict:
        """Training metadata (features, sample counts, model kind) if loaded."""
        cls._ensure()
        if cls._bundle is None:
            return {}
        return dict(cls._bundle.get("meta", {}))
