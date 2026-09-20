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
from maverick.parser import parse_eml
from maverick.parser.received import parse_received_header

client = TestClient(app)
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_bytes(filename: str) -> bytes:
    path = os.path.normpath(os.path.join(SAMPLES_DIR, filename))
    with open(path, "rb") as f:
        return f.read()


def test_health_check():
    """Verify GET /health returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "maverick-parser"


def test_api_parse_clean_upload():
    """Verify POST /parse with uploaded .eml file."""
    content = get_sample_bytes("sample_clean.eml")
    response = client.post(
        "/parse",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()

    # Core metadata
    assert data["subject"] == "[ALERT] Urgent SOC Investigation Briefing - Ref #9042"
    assert "security-alert@corp-defense.com" in data["from_addr"]
    assert "analyst@target-corp.internal" in data["to_addrs"]
    assert data["message_id"] == "<20260918101528.9ZzY8712@corp-defense.com>"

    # Bodies
    assert "Suspicious outbound beaconing activity detected" in data["body_plain"]
    assert "<h2 style=" in data["body_html"]

    # Attachments
    assert len(data["attachments"]) == 1
    att = data["attachments"][0]
    assert att["filename"] == "Incident_Report_9042.pdf"
    assert att["content_type"] == "application/pdf"
    assert att["size_bytes"] > 0
    assert len(att["md5"]) == 32
    assert len(att["sha256"]) == 64
    # Bytes excluded by default
    assert "content_base64" not in att

    # Received chain
    assert len(data["received_chain"]) == 3
    assert data["received_chain"][0]["from_ip"] == "10.20.30.40"
    assert data["received_chain"][2]["by_host"] == "mailserver.target-corp.internal"


def test_api_parse_with_attachment_bytes():
    """Verify POST /parse with include_attachment_bytes=true returns base64 content."""
    content = get_sample_bytes("sample_clean.eml")
    response = client.post(
        "/parse?include_attachment_bytes=true",
        files={"file": ("sample_clean.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    att = data["attachments"][0]
    assert "content_base64" in att
    assert att["content_base64"] is not None
    assert len(att["content_base64"]) > 0


def test_api_parse_raw_body():
    """Verify POST /parse with raw bytes in request body."""
    content = get_sample_bytes("sample_nested_multipart.eml")
    response = client.post(
        "/parse",
        content=content,
        headers={"Content-Type": "message/rfc822"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Fwd: Forensic Investigation: Phishing Evasion Package"
    assert len(data["attachments"]) == 3


def test_api_parse_malformed_file():
    """Verify POST /parse with malformed sample returns 200 and warnings."""
    content = get_sample_bytes("sample_edge_malformed.eml")
    response = client.post(
        "/parse",
        files={"file": ("sample_edge_malformed.eml", content, "message/rfc822")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] is None
    assert len(data["forensic_warnings"]) > 0


def test_api_empty_payload_error():
    """Verify POST /parse with empty body returns 400 Bad Request."""
    response = client.post("/parse", content=b"")
    assert response.status_code == 400
    assert "No .eml file or raw email content provided" in response.json()["detail"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
