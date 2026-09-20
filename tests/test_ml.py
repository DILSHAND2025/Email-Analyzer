"""Unit tests for MAVERICK Machine Learning Phishing Classifier (Module 4)."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution and IDE analyzers
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.ml import (
    InfluentialTerm,
    MLClassificationResult,
    MLClassifier,
    clean_text,
    classify_parsed_email,
    classify_text,
    get_classifier,
)
from maverick.parser import parse_eml

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_startup_loading():
    """Verify vectorizer and model are loaded into memory at startup."""
    classifier = get_classifier()
    assert classifier.is_loaded is True
    assert classifier.vectorizer is not None
    assert classifier.model is not None
    assert len(classifier.vectorizer.vocabulary_) == 5000


def test_phishing_classification_and_terms():
    """Verify high phishing probability and influential terms extraction for phishing text."""
    phishing_text = (
        "URGENT: Your account has been suspended due to suspicious activity. "
        "Click the link below immediately to verify your paypal credentials and secure your money. "
        "Failure to act within 24 hours will result in permanent account termination."
    )

    result = classify_text(phishing_text, top_k=6)

    assert result.predicted_label == "phishing"
    assert result.phishing_probability >= 0.85
    assert result.confidence >= 0.85
    assert len(result.top_influential_terms) > 0

    # Inspect top terms driving the phishing classification
    terms = [t.term for t in result.top_influential_terms]
    assert any(w in terms for w in ["click", "account", "money", "immediately", "paypal", "urgent"])

    # For phishing, top terms should have positive impact
    for t in result.top_influential_terms:
        assert t.impact > 0
        assert t.indicator == "PHISHING"
        assert t.tfidf > 0


def test_benign_classification_and_terms():
    """Verify low phishing probability and influential terms extraction for legitimate text."""
    benign_text = (
        "Hello team, attached is the quarterly financial research paper and meeting summary. "
        "Thanks for your review, feedback, and dedication regarding the university linguistics project."
    )

    result = classify_text(benign_text, top_k=6)

    assert result.predicted_label == "benign"
    assert result.phishing_probability <= 0.15
    assert result.confidence >= 0.85
    assert len(result.top_influential_terms) > 0

    # Inspect top terms driving the benign classification
    terms = [t.term for t in result.top_influential_terms]
    assert any(w in terms for w in ["thanks", "attached", "university", "review", "linguistics", "project"])

    # For benign, top terms should have negative impact (pulling towards class 0)
    for t in result.top_influential_terms:
        assert t.impact < 0
        assert t.indicator == "BENIGN"


def test_classify_parsed_email():
    """Verify inference directly against a ParsedEmail object."""
    path = get_sample_path("sample_phishing.eml")
    parsed = parse_eml(path)

    result = classify_parsed_email(parsed, top_k=5)
    assert result.predicted_label == "phishing"
    assert result.phishing_probability > 0.9
    assert len(result.top_influential_terms) > 0


def test_empty_and_short_edge_cases():
    """Verify resilient handling of empty or very short inputs without exceptions."""
    empty_res = classify_text("")
    assert empty_res.predicted_label == "benign"
    assert empty_res.phishing_probability == 0.05
    assert empty_res.top_influential_terms == []

    whitespace_res = classify_text("    \n\t   ")
    assert whitespace_res.predicted_label == "benign"

    short_res = classify_text("hi")
    assert short_res.predicted_label == "benign"
    assert short_res.top_influential_terms == []


def test_clean_text_preprocessor():
    """Verify text preprocessing normalizes URLs, emails, and tags."""
    raw = "<p>Visit https://secure-bank.com or email alert@bank.com now!</p>"
    cleaned = clean_text(raw)
    assert "url_token" in cleaned
    assert "email_token" in cleaned
    assert "<p>" not in cleaned
    assert "https://" not in cleaned


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
