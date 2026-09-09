"""
ThreatDetect AI inference pipeline.

Public API:
    from AI_ENGINE.pipeline import analyze_ai
    result = analyze_ai(email_data)

AI results are evidence. The existing deterministic forensic/risk engine
remains authoritative for the final ThreatDetect verdict.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import joblib

from .contracts import AIResult, ModelResult, normalize_email_data


BASE_DIR = Path(__file__).resolve().parent

MODEL1_PATH = BASE_DIR / "model1" / "model1.pkl"
MODEL1_VECTORIZER_PATH = BASE_DIR / "model1" / "vectorizer.pkl"

MODEL2_PATH = BASE_DIR / "model2" / "model2.pkl"
MODEL2_VECTORIZER_PATH = BASE_DIR / "model2" / "model2_tfidf.pkl"

MODEL1_VERSION = os.getenv("THREATDETECT_MODEL1_VERSION", "1.0.0")
MODEL2_VERSION = os.getenv("THREATDETECT_MODEL2_VERSION", "1.0.0")

# The current Model 2 artifact was observed to use:
# 0 = non-BEC, 1 = BEC.
# Keep this configurable until the training dataset formally documents it.
MODEL2_BEC_LABEL = os.getenv("THREATDETECT_MODEL2_BEC_LABEL", "1")

_model1: Any | None = None
_model1_vectorizer: Any | None = None
_model2: Any | None = None
_model2_vectorizer: Any | None = None


def _load_model1() -> tuple[Any, Any]:
    global _model1, _model1_vectorizer
    if _model1 is None:
        _model1 = joblib.load(MODEL1_PATH)
    if _model1_vectorizer is None:
        _model1_vectorizer = joblib.load(MODEL1_VECTORIZER_PATH)
    return _model1, _model1_vectorizer


def _load_model2() -> tuple[Any, Any]:
    global _model2, _model2_vectorizer
    if _model2 is None:
        _model2 = joblib.load(MODEL2_PATH)
    if _model2_vectorizer is None:
        _model2_vectorizer = joblib.load(MODEL2_VECTORIZER_PATH)
    return _model2, _model2_vectorizer


def _validate_compatibility(model: Any, vectorizer: Any, name: str) -> None:
    model_features = getattr(model, "n_features_in_", None)
    if model_features is None and hasattr(model, "coef_"):
        model_features = model.coef_.shape[1]

    vocabulary = getattr(vectorizer, "vocabulary_", None)
    vectorizer_features = len(vocabulary) if vocabulary is not None else None

    if (
        model_features is not None
        and vectorizer_features is not None
        and model_features != vectorizer_features
    ):
        raise ValueError(
            f"{name} model/vectorizer mismatch: "
            f"model={model_features}, vectorizer={vectorizer_features}"
        )


def _model1_result(email: dict[str, Any]) -> ModelResult:
    model, vectorizer = _load_model1()
    _validate_compatibility(model, vectorizer, "Model 1")

    text = f"{email['subject']} {email['body']}".strip()
    features = vectorizer.transform([text])

    prediction = str(model.predict(features)[0])
    probabilities = model.predict_proba(features)[0]
    probability_map = {
        str(label): float(probability)
        for label, probability in zip(model.classes_, probabilities)
    }

    spam_probability = probability_map.get("spam", 0.0)

    return {
        "model": "Model 1 - Spam/Phishing Detection",
        "model_version": MODEL1_VERSION,
        "label": prediction,
        "probability": float(probability_map.get(prediction, 0.0)),
        "score": round(spam_probability * 100.0, 2),
        "findings": [f"Spam probability: {spam_probability * 100.0:.2f}%"],
        "details": {
            "prediction": prediction,
            "class_probabilities": probability_map,
            "feature_count": int(features.shape[1]),
        },
    }


def _model2_result(email: dict[str, Any]) -> ModelResult:
    model, vectorizer = _load_model2()
    _validate_compatibility(model, vectorizer, "Model 2")

    # Exact text construction used by the Model 2 training script.
    text = (
        "SUBJECT: "
        + email["subject"]
        + " BODY: "
        + email["body"]
    ).strip()

    features = vectorizer.transform([text])
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    probability_map = {
        str(label): float(probability)
        for label, probability in zip(model.classes_, probabilities)
    }

    bec_probability = probability_map.get(MODEL2_BEC_LABEL, 0.0)
    is_bec = str(prediction) == MODEL2_BEC_LABEL

    return {
        "model": "Model 2 - BEC Detection",
        "model_version": MODEL2_VERSION,
        "label": "bec" if is_bec else "non_bec",
        "probability": float(bec_probability),
        "score": round(bec_probability * 100.0, 2),
        "findings": [f"BEC probability: {bec_probability * 100.0:.2f}%"],
        "details": {
            # Preserve the classifier's native prediction type. Model 2
            # currently uses numeric classes (0/1), so the API should expose
            # 0 or 1 rather than converting it to the string "0"/"1".
            "prediction": (
                int(prediction)
                if hasattr(prediction, "__int__")
                else str(prediction)
            ),
            "class_probabilities": probability_map,
            "bec_label": MODEL2_BEC_LABEL,
            "feature_count": int(features.shape[1]),
        },
    }


def analyze_ai(email_data: dict[str, Any]) -> AIResult:
    """Run both trained models and return model-level evidence."""
    email = normalize_email_data(email_data)

    return {
        "model_results": [
            _model1_result(email),
            _model2_result(email),
        ],
        "metadata": {
            "engine": "ThreatDetect AI_ENGINE",
            "engine_version": "1.0.0",
            "models": [
                {
                    "name": "threatdetect-spam",
                    "version": MODEL1_VERSION,
                    "type": "tfidf-logistic-regression",
                },
                {
                    "name": "threatdetect-bec",
                    "version": MODEL2_VERSION,
                    "type": "tfidf-logistic-regression",
                },
            ],
        },
    }


def reset_model_cache() -> None:
    """Clear cached artifacts; useful for controlled tests/reloads."""
    global _model1, _model1_vectorizer, _model2, _model2_vectorizer
    _model1 = None
    _model1_vectorizer = None
    _model2 = None
    _model2_vectorizer = None
