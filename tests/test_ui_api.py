"""Tests for MAVERICK Demo Web Interface & Static Asset Endpoints."""

import pytest
from fastapi.testclient import TestClient

from maverick.api import app

client = TestClient(app)


def test_ui_index_html():
    """Verify GET / returns 200 with HTML and required demo interface controls."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    html = resp.text
    assert "MAVERICK" in html
    assert "dropzone" in html
    assert "run-btn" in html
    assert "res-verdict-badge" in html
    assert "download-pdf-btn" in html
    assert "sample_phishing.eml" in html


def test_ui_css_asset():
    """Verify GET /ui/style.css returns valid CSS with text/css content type."""
    resp = client.get("/ui/style.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers.get("content-type", "")
    assert ":root" in resp.text
    assert "verdict-critical" in resp.text


def test_ui_js_asset():
    """Verify GET /ui/app.js returns valid JS with application/javascript content type."""
    resp = client.get("/ui/app.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers.get("content-type", "")
    assert "generate-report" in resp.text
    assert "renderResults" in resp.text


def test_demo_samples_available():
    """Verify bundled sample presets can be retrieved by the frontend."""
    samples = [
        "sample_phishing.eml",
        "sample_clean.eml",
        "sample_auth_spoofed.eml",
        "sample_malware.eml",
    ]
    for s in samples:
        resp = client.get(f"/demo/sample/{s}")
        assert resp.status_code == 200, f"Failed for sample {s}: {resp.text}"
        assert len(resp.content) > 50


def test_demo_sample_not_found():
    """Verify unknown sample returns 404."""
    resp = client.get("/demo/sample/invalid_sample.eml")
    assert resp.status_code == 404


def test_ui_asset_not_found():
    """Verify unauthorized or nonexistent asset returns 404."""
    resp = client.get("/ui/secret.env")
    assert resp.status_code == 404
