"""Integration tests for MAVERICK Attachment Forensics API (POST /analyze-attachment)."""

import base64
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
from maverick.forensics.analyzer import EICAR_SHA256, EICAR_SIG

client = TestClient(app)
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_bytes(filename: str) -> bytes:
    path = os.path.normpath(os.path.join(SAMPLES_DIR, filename))
    with open(path, "rb") as f:
        return f.read()


def test_api_analyze_attachment_direct_eicar_upload():
    """Verify POST /analyze-attachment with directly uploaded EICAR payload."""
    response = client.post(
        "/analyze-attachment",
        files={"file": ("test_malware.bin", EICAR_SIG, "application/octet-stream")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_malware.bin"
    assert data["hashes"]["sha256"] == EICAR_SHA256
    assert data["verdict"] == "malicious"
    assert any("EICAR" in ind for ind in data["suspicious_indicators"])


def test_api_analyze_attachment_macro_upload():
    """Verify POST /analyze-attachment with macro-enabled Word document."""
    data = get_sample_bytes("sample_macro_benign.docx")

    response = client.post(
        "/analyze-attachment",
        files={
            "file": (
                "sample_macro_benign.docx",
                data,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        },
    )

    assert response.status_code == 200
    res_data = response.json()
    assert res_data["macro_present"] is True
    assert res_data["mismatch"] is False
    assert any("VBA macros detected" in ind for ind in res_data["suspicious_indicators"])


def test_api_analyze_attachment_parsed_email_json():
    """Verify pipeline chaining: /parse JSON piped into /analyze-attachment."""
    # Create sample ParsedEmail JSON with an attachment
    parsed_json = {
        "headers": {"From": "test@domain.com", "Subject": "Attachment Analysis"},
        "body_plain": "Attached is the document.",
        "attachments": [
            {
                "filename": "security_test.com",
                "content_type": "application/octet-stream",
                "size_bytes": len(EICAR_SIG),
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha256": EICAR_SHA256,
                "content_base64": base64.b64encode(EICAR_SIG).decode("ascii"),
            }
        ],
    }

    response = client.post("/analyze-attachment", json=parsed_json)
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_type"] == "static_forensics"
    assert data["total_attachments"] == 1
    assert data["suspicious_count"] == 1
    assert data["attachments"][0]["verdict"] == "malicious"


def test_api_analyze_attachment_empty_error():
    """Verify empty payload returns HTTP 400 Bad Request."""
    response = client.post("/analyze-attachment", content=b"   ")
    assert response.status_code == 400
    assert "empty payload" in response.json()["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
