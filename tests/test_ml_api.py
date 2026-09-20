"""Integration tests for MAVERICK FastAPI /classify endpoint."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution and IDE analyzers
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from starlette.testclient import TestClient

from maverick.api import app

client = TestClient(app)
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_bytes(filename: str) -> bytes:
    path = os.path.normpath(os.path.join(SAMPLES_DIR, filename))
    with open(path, "rb") as f:
        return f.read()


def test_api_classify_with_file_upload():
    """Verify POST /classify with uploaded .eml file."""
    content = get_sample_bytes("sample_phishing.eml")
    response = client.post(
        "/classify",
        files={"file": ("sample_phishing.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["predicted_label"] == "phishing"
    assert data["phishing_probability"] > 0.9
    assert len(data["top_influential_terms"]) > 0


def test_api_classify_with_parsed_email_json():
    """Verify pipeline chaining: /parse JSON piped to /classify."""
    content = get_sample_bytes("sample_clean.eml")

    # 1. Parse email
    parse_resp = client.post(
        "/parse",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )
    assert parse_resp.status_code == 200
    parsed_json = parse_resp.json()

    # 2. Pipe to /classify
    classify_resp = client.post(
        "/classify",
        json=parsed_json,
    )
    assert classify_resp.status_code == 200
    ml_data = classify_resp.json()

    assert "phishing_probability" in ml_data
    assert "predicted_label" in ml_data
    assert "top_influential_terms" in ml_data


def test_api_classify_with_raw_text_json():
    """Verify POST /classify with { 'text': '...' } payload."""
    payload = {
        "text": "URGENT: Click to verify your bank account and claim your free money now!"
    }
    response = client.post("/classify", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["predicted_label"] == "phishing"
    assert data["phishing_probability"] > 0.8
    assert any(t["term"] in ["click", "account", "money", "free"] for t in data["top_influential_terms"])


def test_api_classify_empty_error():
    """Verify POST /classify with empty body returns 400 Bad Request."""
    response = client.post("/classify", content=b"")
    assert response.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
