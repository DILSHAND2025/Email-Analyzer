"""Integration tests for MAVERICK FastAPI /auth-check endpoint."""

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


def test_api_auth_check_file_upload_pass():
    """Verify POST /auth-check with uploaded legitimate EML file."""
    content = get_sample_bytes("sample_auth_pass.eml")
    response = client.post(
        "/auth-check",
        files={"file": ("sample_auth_pass.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["spf"] == "pass"
    assert data["dkim"] == "pass"
    assert data["dmarc"] == "pass"
    assert data["aligned"] is True
    assert data["spf_aligned"] is True
    assert data["dkim_aligned"] is True
    assert data["from_domain"] == "corp-defense.com"


def test_api_auth_check_file_upload_spoofed():
    """Verify POST /auth-check with uploaded spoofed EML file."""
    content = get_sample_bytes("sample_auth_spoofed.eml")
    response = client.post(
        "/auth-check",
        files={"file": ("sample_auth_spoofed.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["from_domain"] == "trusted-bank.com"
    assert data["spf_domain"] == "compromised-relay.xyz"
    assert data["aligned"] is False
    assert data["dmarc"] == "fail"


def test_api_auth_check_pipeline_chaining():
    """Verify pipeline chaining: /parser output piped as JSON to /auth-check."""
    clean_bytes = get_sample_bytes("sample_clean.eml")
    
    # 1. Call /parse
    parse_resp = client.post(
        "/parse",
        files={"file": ("sample_clean.eml", clean_bytes, "message/rfc822")},
    )
    assert parse_resp.status_code == 200
    parsed_json = parse_resp.json()

    # 2. Pipe ParsedEmail JSON to /auth-check
    auth_resp = client.post(
        "/auth-check",
        json=parsed_json,
    )
    assert auth_resp.status_code == 200
    auth_data = auth_resp.json()

    assert auth_data["spf"] == "pass"
    assert auth_data["dkim"] == "pass"
    assert auth_data["from_domain"] == "corp-defense.com"
    assert auth_data["aligned"] is True


def test_api_auth_check_raw_body():
    """Verify POST /auth-check with raw EML content in body."""
    content = get_sample_bytes("sample_no_auth_header.eml")
    response = client.post(
        "/auth-check",
        content=content,
        headers={"Content-Type": "message/rfc822"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verification_source"] == "direct_verification"


def test_api_auth_check_empty_error():
    """Verify POST /auth-check with empty body returns 400 Bad Request."""
    response = client.post("/auth-check", content=b"")
    assert response.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
