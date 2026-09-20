"""Integration tests for MAVERICK FastAPI /extract-iocs endpoint."""

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


def test_api_extract_iocs_with_file_upload():
    """Verify POST /extract-iocs with uploaded .eml file."""
    content = get_sample_bytes("sample_ioc_rich.eml")
    response = client.post(
        "/extract-iocs",
        files={"file": ("sample_ioc_rich.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # Verify IP indicators
    public_ips = [item["ip"] for item in data["ips"]]
    assert "198.51.100.45" in public_ips
    assert "203.0.113.88" in public_ips

    # Verify excluded private IPs
    excluded_ips = [item["ip"] for item in data["excluded_ips"]]
    assert "10.0.0.15" in excluded_ips
    assert "127.0.0.1" in excluded_ips

    # Verify URLs
    assert "https://phish-secure.xyz/portal?token=abc" in data["urls"]
    assert "https://c2-control.net/payload.exe" in data["urls"]

    # Verify domains
    assert "phish-secure.xyz" in data["domains"]
    assert "c2-control.net" in data["domains"]

    # Verify mentioned emails
    assert "whistleblower@external-leak.org" in data["emails"]
    assert "sender@alert-sec.com" not in data["emails"]


def test_api_extract_iocs_pipeline_chaining():
    """Verify pipeline chaining: /parser JSON output piped to /extract-iocs."""
    content = get_sample_bytes("sample_ioc_rich.eml")

    # 1. Parse email
    parse_resp = client.post(
        "/parse",
        files={"file": ("sample_ioc_rich.eml", content, "message/rfc822")},
    )
    assert parse_resp.status_code == 200
    parsed_json = parse_resp.json()

    # 2. Pipe to /extract-iocs
    ioc_resp = client.post(
        "/extract-iocs",
        json=parsed_json,
    )
    assert ioc_resp.status_code == 200
    ioc_data = ioc_resp.json()

    assert len(ioc_data["ips"]) >= 2
    assert len(ioc_data["excluded_ips"]) >= 2
    assert len(ioc_data["urls"]) >= 3


def test_api_extract_iocs_empty_error():
    """Verify POST /extract-iocs with empty payload returns 400 Bad Request."""
    response = client.post("/extract-iocs", content=b"")
    assert response.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
