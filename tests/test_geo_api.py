"""Integration tests for MAVERICK IP Geolocation Endpoint (POST /geolocate)."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from starlette.testclient import TestClient

from maverick.api import app
from maverick.intel.geo import clear_geo_cache

client = TestClient(app)
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_bytes(filename: str) -> bytes:
    path = os.path.normpath(os.path.join(SAMPLES_DIR, filename))
    with open(path, "rb") as f:
        return f.read()


@pytest.fixture(autouse=True)
def reset_cache():
    clear_geo_cache()
    yield
    clear_geo_cache()


def test_api_geolocate_with_ips_json():
    """Verify POST /geolocate with a direct JSON payload of IP addresses."""
    mock_batch = [
        {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "region": "VA",
            "regionName": "Virginia",
            "city": "Ashburn",
            "as": "AS15169 Google LLC",
            "isp": "Google LLC",
            "query": "8.8.8.8",
        },
        {
            "status": "success",
            "country": "Australia",
            "countryCode": "AU",
            "region": "QLD",
            "regionName": "Queensland",
            "city": "South Brisbane",
            "as": "AS13335 Cloudflare, Inc.",
            "isp": "Cloudflare, Inc",
            "query": "1.1.1.1",
        },
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_batch
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        response = client.post("/geolocate", json={"ips": ["8.8.8.8", "1.1.1.1"]})

    assert response.status_code == 200
    data = response.json()
    assert data["enrichment_type"] == "inferred_enrichment"
    assert "inferred enrichment" in data["disclaimer"].lower()
    assert data["total_queried"] == 2
    assert len(data["results"]) == 2

    res0 = data["results"][0]
    assert res0["ip"] == "8.8.8.8"
    assert res0["country"] == "United States"
    assert res0["asn"] == "AS15169 Google LLC"
    assert res0["evidence_type"] == "inferred_enrichment"


def test_api_geolocate_with_ioc_set_pipeline_chaining():
    """Verify pipeline chaining: /extract-iocs output piped into /geolocate."""
    content = get_sample_bytes("sample_ioc_rich.eml")

    # 1. Harvest IOCs
    ioc_resp = client.post(
        "/extract-iocs",
        files={"file": ("sample_ioc_rich.eml", content, "message/rfc822")},
    )
    assert ioc_resp.status_code == 200
    ioc_data = ioc_resp.json()

    mock_batch = [
        {
            "status": "success",
            "country": "United States",
            "query": "198.51.100.45",
            "city": "Dallas",
            "as": "AS64496 Example Net",
            "isp": "Example Telecom",
        },
        {
            "status": "success",
            "country": "United States",
            "query": "203.0.113.88",
            "city": "Seattle",
            "as": "AS64500 Example Net 2",
            "isp": "Example Telecom 2",
        },
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_batch
    ).encode("utf-8")

    # 2. Pipe IOCSet into /geolocate
    with patch("urllib.request.urlopen", mock_urlopen):
        geo_resp = client.post("/geolocate", json=ioc_data)

    assert geo_resp.status_code == 200
    geo_data = geo_resp.json()
    assert geo_data["enrichment_type"] == "inferred_enrichment"
    assert geo_data["total_queried"] >= 1
    # Verify private IPs were filtered out and not in results
    result_ips = [r["ip"] for r in geo_data["results"]]
    assert "10.0.0.15" not in result_ips
    assert "127.0.0.1" not in result_ips


def test_api_geolocate_with_file_upload():
    """Verify POST /geolocate accepts .eml file directly and runs pipeline."""
    content = get_sample_bytes("sample_ioc_rich.eml")

    mock_batch = [
        {
            "status": "success",
            "country": "United States",
            "query": "198.51.100.45",
            "as": "AS64496 Example Net",
        },
        {
            "status": "success",
            "country": "United States",
            "query": "203.0.113.88",
            "as": "AS64500 Example Net 2",
        },
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_batch
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        response = client.post(
            "/geolocate",
            files={"file": ("sample_ioc_rich.eml", content, "message/rfc822")},
        )

    assert response.status_code == 200
    data = response.json()
    assert data["enrichment_type"] == "inferred_enrichment"
    assert data["total_queried"] >= 1


def test_api_geolocate_empty_error():
    """Verify empty payload returns HTTP 400 Bad Request."""
    response = client.post("/geolocate", content=b"   ")
    assert response.status_code == 400
    assert "empty payload" in response.json()["detail"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
