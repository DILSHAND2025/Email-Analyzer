"""Integration tests for MAVERICK User Submission & Admin Review Workflow."""

import os
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from maverick.api import app, REPORTS_DIR
from maverick.db import init_db

client = TestClient(app)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure database tables exist and mock external geo lookups for fast execution."""
    init_db()
    with patch("maverick.intel.geo.IPGeoLocator._fetch_batch", return_value={}):
        yield


def test_reporter_submission_workflow():
    """
    Test public reporter submission endpoint:
    - User uploads .eml
    - Full pipeline executes in background
    - PDF persisted to data/reports/
    - Submission stored in SQLite
    - Response strictly contains confirmation only (NO verdict/evidence leak)
    """
    sample_path = os.path.join(SAMPLES_DIR, "sample_clean.eml")
    with open(sample_path, "rb") as f:
        eml_bytes = f.read()

    resp = client.post(
        "/api/submissions",
        files={"file": ("sample_clean.eml", eml_bytes, "message/rfc822")},
    )

    assert resp.status_code == 201
    data = resp.json()

    assert data["status"] == "success"
    assert "case_id" in data
    assert data["case_id"].startswith("MAV-")
    assert data["filename"] == "sample_clean.eml"

    # Strict isolation: reporter response must NOT leak verdict or evidence
    assert "verdict" not in data
    assert "risk_score" not in data
    assert "full_report_json" not in data
    assert "ml_findings" not in data

    # Verify PDF report was written to disk
    case_id = data["case_id"]
    pdf_path = os.path.join(REPORTS_DIR, f"MAVERICK-Report-{case_id}.pdf")
    assert os.path.isfile(pdf_path), f"Persisted PDF missing at {pdf_path}"


def test_admin_list_and_filter_submissions():
    """Test analyst listing, priority sorting, and filtering."""
    # Submit a phishing sample (should score Medium/High/Critical)
    sample_path = os.path.join(SAMPLES_DIR, "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        eml_bytes = f.read()

    sub_resp = client.post(
        "/api/submissions",
        files={"file": ("sample_phishing.eml", eml_bytes, "message/rfc822")},
    )
    assert sub_resp.status_code == 201
    phish_case_id = sub_resp.json()["case_id"]

    # List all
    resp = client.get("/api/submissions")
    assert resp.status_code == 200
    data = resp.json()
    assert "metrics" in data
    assert "submissions" in data
    assert data["metrics"]["total"] >= 1
    assert data["metrics"]["new"] >= 1

    case_ids = [s["case_id"] for s in data["submissions"]]
    assert phish_case_id in case_ids

    # Filter by status: New
    new_resp = client.get("/api/submissions?status=New")
    assert new_resp.status_code == 200
    for s in new_resp.json()["submissions"]:
        assert s["status"].lower() == "new"


def test_admin_get_submission_detail():
    """Test analyst fetching full forensic dossier by Case ID."""
    sample_path = os.path.join(SAMPLES_DIR, "sample_clean.eml")
    with open(sample_path, "rb") as f:
        eml_bytes = f.read()

    sub_resp = client.post(
        "/api/submissions",
        files={"file": ("clean_for_detail.eml", eml_bytes, "message/rfc822")},
    )
    case_id = sub_resp.json()["case_id"]

    resp = client.get(f"/api/submissions/{case_id}")
    assert resp.status_code == 200
    data = resp.json()

    sub = data["submission"]
    assert sub["case_id"] == case_id
    assert "verdict" in sub
    assert "risk_score" in sub
    assert isinstance(sub["full_report_json"], dict)
    assert "threat_assessment" in sub["full_report_json"]
    assert data["pdf_download_url"] == f"/api/submissions/{case_id}/pdf"


def test_admin_status_toggle():
    """Test analyst toggling submission status between New and Reviewed."""
    sample_path = os.path.join(SAMPLES_DIR, "sample_clean.eml")
    with open(sample_path, "rb") as f:
        eml_bytes = f.read()

    sub_resp = client.post(
        "/api/submissions",
        files={"file": ("toggle_test.eml", eml_bytes, "message/rfc822")},
    )
    case_id = sub_resp.json()["case_id"]

    # Mark as Reviewed
    patch_resp = client.patch(
        f"/api/submissions/{case_id}/status",
        json={"status": "Reviewed"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "Reviewed"

    # Revert to New
    revert_resp = client.patch(
        f"/api/submissions/{case_id}/status",
        json={"status": "New"},
    )
    assert revert_resp.status_code == 200
    assert revert_resp.json()["status"] == "New"

    # Invalid status
    invalid_resp = client.patch(
        f"/api/submissions/{case_id}/status",
        json={"status": "UnknownStatus"},
    )
    assert invalid_resp.status_code == 400


def test_admin_download_pdf_report():
    """Test analyst downloading persisted PDF report file."""
    sample_path = os.path.join(SAMPLES_DIR, "sample_clean.eml")
    with open(sample_path, "rb") as f:
        eml_bytes = f.read()

    sub_resp = client.post(
        "/api/submissions",
        files={"file": ("pdf_download_test.eml", eml_bytes, "message/rfc822")},
    )
    case_id = sub_resp.json()["case_id"]

    pdf_resp = client.get(f"/api/submissions/{case_id}/pdf")
    assert pdf_resp.status_code == 200
    assert "application/pdf" in pdf_resp.headers.get("content-type", "")
    assert pdf_resp.content.startswith(b"%PDF")
    assert len(pdf_resp.content) > 1000


def test_web_page_routes():
    """Verify distinct routes for user submit page, admin dashboard, and demo."""
    # User submission page (GET / and GET /submit)
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "text/html" in r_root.headers.get("content-type", "")
    assert "Report a Suspicious Email" in r_root.text
    assert "submit.js" in r_root.text

    r_submit = client.get("/submit")
    assert r_submit.status_code == 200
    assert "Report a Suspicious Email" in r_submit.text

    # Admin analyst dashboard (GET /admin)
    r_admin = client.get("/admin")
    assert r_admin.status_code == 200
    assert "text/html" in r_admin.headers.get("content-type", "")
    assert "Security Analyst Operations" in r_admin.text
    assert "admin.js" in r_admin.text
    assert "admin.css" in r_admin.text

    # Demo interface preserved (GET /demo)
    r_demo = client.get("/demo")
    assert r_demo.status_code == 200
    assert "Automated Forensic Analysis Pipeline" in r_demo.text
    assert "app.js" in r_demo.text

    # Static assets
    assert client.get("/ui/submit.js").status_code == 200
    assert client.get("/ui/admin.js").status_code == 200
    assert client.get("/ui/admin.css").status_code == 200
