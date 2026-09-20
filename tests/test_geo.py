"""Unit tests for MAVERICK IP Geolocation & ASN Enrichment (Module 5)."""

import io
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.intel.geo import (
    IPGeoLocator,
    clear_geo_cache,
    geolocate_ioc_set,
    geolocate_ips,
    get_geolocator,
    is_public_ip,
)
from maverick.intel.models import GeoEnrichmentReport, GeoResult, IOCSet, IPIndicator


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset the session cache before each test."""
    clear_geo_cache()
    yield
    clear_geo_cache()


def test_public_ip_filtering_helper():
    """Verify is_public_ip correctly distinguishes public vs RFC 1918 / loopback IPs."""
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("203.0.113.88") is True
    assert is_public_ip("10.0.0.1") is False       # RFC 1918
    assert is_public_ip("172.16.0.5") is False     # RFC 1918
    assert is_public_ip("192.168.1.1") is False    # RFC 1918
    assert is_public_ip("127.0.0.1") is False      # Loopback
    assert is_public_ip("invalid-ip") is False


def test_geolocate_batch_success():
    """Verify batch lookup parses country, region, city, ASN, and ISP with inferred enrichment flags."""
    mock_response = [
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
        mock_response
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        report = geolocate_ips(["8.8.8.8", "1.1.1.1"])

    assert isinstance(report, GeoEnrichmentReport)
    assert report.total_queried == 2
    assert report.cache_hits == 0
    assert report.errors_count == 0
    assert report.enrichment_type == "inferred_enrichment"
    assert "inferred enrichment" in report.disclaimer.lower()

    # Verify first IP
    res_google = report.results[0]
    assert res_google.ip == "8.8.8.8"
    assert res_google.status == "success"
    assert res_google.country == "United States"
    assert res_google.country_code == "US"
    assert res_google.region == "Virginia"
    assert res_google.city == "Ashburn"
    assert res_google.asn == "AS15169 Google LLC"
    assert res_google.isp == "Google LLC"
    assert res_google.source == "ip-api.com"
    assert res_google.evidence_type == "inferred_enrichment"

    # Verify second IP
    res_cf = report.results[1]
    assert res_cf.ip == "1.1.1.1"
    assert res_cf.status == "success"
    assert res_cf.country == "Australia"
    assert res_cf.asn == "AS13335 Cloudflare, Inc."


def test_in_memory_session_caching():
    """Verify identical IPs are served from memory cache without duplicate HTTP requests."""
    locator = IPGeoLocator()

    mock_response = [
        {
            "status": "success",
            "country": "United States",
            "query": "8.8.8.8",
            "as": "AS15169 Google LLC",
        }
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_response
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        # 1. First lookup: causes 1 network call
        rep1 = locator.geolocate_ips(["8.8.8.8"])
        assert rep1.cache_hits == 0
        assert mock_urlopen.call_count == 1
        assert locator.cache_size == 1

        # 2. Second lookup: served from in-memory cache
        rep2 = locator.geolocate_ips(["8.8.8.8"])
        assert rep2.cache_hits == 1
        assert mock_urlopen.call_count == 1  # No additional network call!
        assert rep2.results[0].country == "United States"


def test_timeout_and_network_error_resilience():
    """Verify network timeouts do not raise uncaught exceptions and return partial error status."""
    locator = IPGeoLocator()

    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("Connection timed out"),
    ):
        report = locator.geolocate_ips(["8.8.8.8", "1.1.1.1"])

    assert report.total_queried == 2
    assert report.errors_count == 2
    for res in report.results:
        assert res.status == "fail"
        assert res.country is None
        assert "Connection timed out" in str(res.error)


def test_rate_limit_429_resilience():
    """Verify HTTP 429 rate limit errors are handled gracefully with informative per-IP error flags."""
    locator = IPGeoLocator()

    http_429 = urllib.error.HTTPError(
        url="http://ip-api.com/batch",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b""),
    )

    with patch("urllib.request.urlopen", side_effect=http_429):
        report = locator.geolocate_ips(["8.8.8.8"])

    assert report.errors_count == 1
    assert report.results[0].status == "fail"
    assert "rate limit exceeded" in str(report.results[0].error).lower()


def test_partial_per_ip_failure():
    """Verify batch response with mixed success and individual IP failure."""
    locator = IPGeoLocator()

    mock_response = [
        {
            "status": "success",
            "country": "United States",
            "query": "8.8.8.8",
            "as": "AS15169 Google LLC",
        },
        {
            "status": "fail",
            "message": "reserved range",
            "query": "240.0.0.1",
        },
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_response
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        report = locator.geolocate_ips(["8.8.8.8", "240.0.0.1"])

    assert report.total_queried == 2
    assert report.errors_count == 1

    succ = next(r for r in report.results if r.ip == "8.8.8.8")
    assert succ.status == "success"
    assert succ.country == "United States"

    fail = next(r for r in report.results if r.ip == "240.0.0.1")
    assert fail.status == "fail"
    assert fail.error == "reserved range"


def test_geolocate_ioc_set_chains_excluding_private_ips():
    """Verify geolocate_ioc_set queries only public routable IPs and skips RFC 1918 private IPs."""
    ioc_set = IOCSet(
        ips=[
            IPIndicator(ip="8.8.8.8", source="header", is_private=False),
            IPIndicator(ip="1.1.1.1", source="body", is_private=False),
        ],
        excluded_ips=[
            IPIndicator(ip="10.0.0.15", source="header", is_private=True),
            IPIndicator(ip="127.0.0.1", source="body", is_private=True),
        ],
    )

    mock_response = [
        {"status": "success", "country": "United States", "query": "8.8.8.8"},
        {"status": "success", "country": "Australia", "query": "1.1.1.1"},
    ]

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(
        mock_response
    ).encode("utf-8")

    with patch("urllib.request.urlopen", mock_urlopen):
        report = geolocate_ioc_set(ioc_set)

    assert report.total_queried == 2
    queried_ips = [r.ip for r in report.results]
    assert "8.8.8.8" in queried_ips
    assert "1.1.1.1" in queried_ips
    assert "10.0.0.15" not in queried_ips
    assert "127.0.0.1" not in queried_ips


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
