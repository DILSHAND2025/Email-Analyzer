"""Integration tests for MAVERICK Forensic Report API endpoints (POST /generate-report, GET /reports/...)."""

import base64
import hashlib
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


def test_api_generate_report_json_default():
    """Verify POST /generate-report returns structured JSON report with embedded base64 PDF and SHA-256 integrity hash."""
    content = get_sample_bytes("sample_phishing.eml")
    response = client.post(
        "/generate-report",
        files={"file": ("sample_phishing.eml", content, "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()

    # Core response wrappers
    assert "case_id" in data
    assert data["case_id"].startswith("MAV-")
    assert "pdf_sha256" in data
    assert "pdf_filename" in data
    assert "pdf_base64" in data
    assert "report" in data

    # Validate embedded PDF integrity
    pdf_bytes = base64.b64decode(data["pdf_base64"])
    assert pdf_bytes.startswith(b"%PDF-")
    computed_hash = hashlib.sha256(pdf_bytes).hexdigest()
    assert data["pdf_sha256"] == computed_hash

    # Validate report sections
    report = data["report"]
    assert "case_metadata" in report
    assert "threat_assessment" in report
    assert "evidence_fusion" in report
    assert "recommendations" in report
    assert len(report["recommendations"]) > 0


def test_api_generate_report_pdf_download():
    """Verify POST /generate-report?format=pdf streams direct binary PDF with headers."""
    content = get_sample_bytes("sample_clean.eml")
    response = client.post(
        "/generate-report?format=pdf",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "attachment" in response.headers["content-disposition"]
    assert "MAVERICK-Report-MAV-" in response.headers["content-disposition"]

    # Header integrity check
    assert "x-case-id" in response.headers
    assert "x-pdf-sha256" in response.headers

    pdf_bytes = response.content
    assert pdf_bytes.startswith(b"%PDF-")
    computed_hash = hashlib.sha256(pdf_bytes).hexdigest()
    assert response.headers["x-pdf-sha256"] == computed_hash


def test_api_generate_report_with_parsed_email_json_chaining():
    """Verify pipeline chaining: /parse JSON piped directly to /generate-report."""
    content = get_sample_bytes("sample_clean.eml")

    # 1. Parse email
    parse_resp = client.post(
        "/parse?include_attachment_bytes=true",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )
    assert parse_resp.status_code == 200
    parsed_json = parse_resp.json()

    # 2. Pipe to /generate-report
    report_resp = client.post("/generate-report", json=parsed_json)
    assert report_resp.status_code == 200
    report_data = report_resp.json()

    assert "case_id" in report_data
    assert "pdf_sha256" in report_data
    assert report_data["report"]["threat_assessment"]["verdict"] == "Low"


def test_api_get_cached_report_endpoints():
    """Verify cached report retrieval by Case ID via GET /reports/{case_id}/pdf and /json."""
    content = get_sample_bytes("sample_phishing.eml")
    gen_resp = client.post(
        "/generate-report",
        files={"file": ("sample_phishing.eml", content, "message/rfc822")},
    )
    assert gen_resp.status_code == 200
    case_id = gen_resp.json()["case_id"]

    # 1. Retrieve PDF
    pdf_resp = client.get(f"/reports/{case_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF-")

    # 2. Retrieve JSON
    json_resp = client.get(f"/reports/{case_id}/json")
    assert json_resp.status_code == 200
    j_data = json_resp.json()
    assert j_data["case_metadata"]["case_id"] == case_id


def test_api_cached_report_not_found():
    """Verify nonexistent Case ID returns HTTP 404."""
    resp = client.get("/reports/MAV-NONEXISTENT-CASE/pdf")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_api_generate_report_empty_payload_error():
    """Verify empty payload returns HTTP 400 Bad Request."""
    response = client.post("/generate-report", content=b"   ")
    assert response.status_code == 400
    assert "empty payload" in response.json()["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
