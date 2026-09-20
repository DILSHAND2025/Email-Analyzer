"""Integration tests for MAVERICK Evidence Fusion API (POST /fuse)."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
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


def test_api_fuse_with_eml_file_upload():
    """Verify POST /fuse orchestrates all modules end-to-end for an uploaded .eml file."""
    content = get_sample_bytes("sample_phishing.eml")
    response = client.post(
        "/fuse",
        files={"file": ("sample_phishing.eml", content, "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()

    assert "risk_score" in data
    assert "verdict" in data
    assert "contributing_factors" in data
    assert "score_breakdown" in data
    assert len(data["contributing_factors"]) > 0

    breakdown = data["score_breakdown"]
    assert "ml_phishing" in breakdown
    assert "authentication" in breakdown
    assert "attachments" in breakdown
    assert "ioc_geo" in breakdown

    # In sample_phishing.eml, ML should be the primary driver
    assert breakdown["ml_phishing"] > 0.30
    assert data["verdict"] in ("Medium", "High", "Critical")


def test_api_fuse_with_parsed_email_json_chaining():
    """Verify pipeline chaining: /parse output piped directly to /fuse."""
    content = get_sample_bytes("sample_clean.eml")

    # 1. Parse email
    parse_resp = client.post(
        "/parse",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )
    assert parse_resp.status_code == 200
    parsed_json = parse_resp.json()

    # 2. Pipe to /fuse
    fuse_resp = client.post("/fuse", json=parsed_json)
    assert fuse_resp.status_code == 200
    fuse_data = fuse_resp.json()

    assert fuse_data["verdict"] == "Low"
    assert fuse_data["risk_score"] < 0.30
    assert "details" in fuse_data
    assert "auth" in fuse_data["details"]
    assert "ml" in fuse_data["details"]


def test_api_fuse_empty_payload_error():
    """Verify empty payload returns HTTP 400 Bad Request."""
    response = client.post("/fuse", content=b"   ")
    assert response.status_code == 400
    assert "empty payload" in response.json()["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
