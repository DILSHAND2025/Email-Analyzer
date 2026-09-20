"""MAVERICK Machine Learning Phishing Classifier (Module 4)."""

from maverick.ml.models import InfluentialTerm, MLClassificationResult
from maverick.ml.classifier import (
    MLClassifier,
    clean_text,
    classify_parsed_email,
    classify_text,
    get_classifier,
)

__all__ = [
    "InfluentialTerm",
    "MLClassificationResult",
    "MLClassifier",
    "clean_text",
    "classify_parsed_email",
    "classify_text",
    "get_classifier",
]
