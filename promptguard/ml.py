"""
promptguard.ml
==============

Runtime prompt-injection classifier — a trained, bundled scikit-learn model.

The artifact (TF-IDF vectorizer + LogisticRegression) is shipped at
``promptguard/data/classifier.joblib`` and produced by ``scripts/train_model.py``.
This module loads it lazily and exposes :class:`MLClassifier`.

If scikit-learn / joblib is not installed, the artifact is missing, or the
artifact cannot predict under the installed scikit-learn version (a training/
runtime version mismatch), the classifier reports unavailable and the detector
falls back to heuristic + statistical scoring. Install the ``ml`` extra to
enable it:

    pip install promptguard[ml]
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

_DATA = Path(__file__).resolve().parent / "data" / "classifier.joblib"


class MLClassifier:
    """Lazily-loaded singleton wrapper around the bundled sklearn model.

    ``available()`` loads the artifact and runs a probe prediction, so a
    scikit-learn version mismatch (the artifact trained under a newer sklearn
    than the runtime) surfaces as ``available() == False`` instead of silently
    scoring every input ``ml=0``.
    """

    _bundle: Optional[Dict] = None
    _loaded: bool = False
    _predict_ok: bool = False

    @classmethod
    def _ensure(cls) -> None:
        if cls._loaded:
            return
        cls._loaded = True
        try:
            import joblib  # type: ignore
            if _DATA.is_file():
                cls._bundle = joblib.load(_DATA)
                # Probe: confirm the model can actually predict with the
                # installed sklearn. A version mismatch between training and
                # runtime (e.g. LogisticRegression.multi_class removed in
                # newer sklearn) makes predict_proba raise; without this probe
                # the detector would silently score every input ml=0 and
                # report ml_available=True, hiding the failure.
                vec = cls._bundle["vectorizer"]
                clf = cls._bundle["model"]
                clf.predict_proba(vec.transform(["probe"]))
                cls._predict_ok = True
        except Exception:
            cls._bundle = None
            cls._predict_ok = False

    @classmethod
    def available(cls) -> bool:
        """True if the artifact loads AND predicts under the installed sklearn."""
        try:
            import sklearn  # type: ignore  # noqa: F401
        except Exception:
            return False
        cls._ensure()
        return cls._bundle is not None and cls._predict_ok

    @classmethod
    def predict_proba(cls, text: str) -> Optional[float]:
        """Return P(injection) in [0, 1], or None if the model is unavailable."""
        cls._ensure()
        if cls._bundle is None or not cls._predict_ok:
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
