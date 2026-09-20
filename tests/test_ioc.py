"""Unit tests for MAVERICK Threat Intelligence & IOC Extraction (Module 3)."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution and IDE analyzers
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.intel import (
    IOCSet,
    IPIndicator,
    URLIndicator,
    clean_url,
    extract_iocs,
    undefang_text,
)
from maverick.parser import parse_eml

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_ip_extraction_and_tagging():
    """Verify IP address harvesting, source tagging ('header' vs 'body'), and private IP filtering."""
    path = get_sample_path("sample_ioc_rich.eml")
    parsed = parse_eml(path)
    iocs = extract_iocs(parsed)

    # Public IPs
    public_ip_map = {item.ip: item for item in iocs.ips}
    assert "198.51.100.45" in public_ip_map
    assert public_ip_map["198.51.100.45"].source == "header"
    assert public_ip_map["198.51.100.45"].is_private is False

    assert "203.0.113.88" in public_ip_map
    assert "body" in public_ip_map["203.0.113.88"].source
    assert public_ip_map["203.0.113.88"].is_private is False

    # Private / Excluded IPs (RFC 1918, loopback)
    excluded_ip_map = {item.ip: item for item in iocs.excluded_ips}
    assert "10.0.0.15" in excluded_ip_map
    assert excluded_ip_map["10.0.0.15"].is_private is True
    assert "RFC 1918" in (excluded_ip_map["10.0.0.15"].notes or "")

    assert "127.0.0.1" in excluded_ip_map
    assert excluded_ip_map["127.0.0.1"].is_private is True
    assert "Loopback" in (excluded_ip_map["127.0.0.1"].notes or "")

    # Ensure private IPs are NOT leaked into the public ips list
    assert "10.0.0.15" not in public_ip_map
    assert "127.0.0.1" not in public_ip_map


def test_url_extraction_from_html_and_defanged():
    """Verify URL harvesting from HTML href/src and un-defanging of plain text URLs."""
    path = get_sample_path("sample_ioc_rich.eml")
    parsed = parse_eml(path)
    iocs = extract_iocs(parsed)

    # 1. Extracted from HTML <a> href
    assert "https://phish-secure.xyz/portal?token=abc" in iocs.urls

    # 2. Extracted from HTML <img> src
    assert "https://tracking.beacon-analytics.com/pixel.gif" in iocs.urls

    # 3. Un-defanged from text: hxxps://c2-control[.]net/payload.exe -> https://c2-control.net/payload.exe
    assert "https://c2-control.net/payload.exe" in iocs.urls


def test_domain_extraction():
    """Verify domains extracted from URLs, hostnames, and body emails."""
    path = get_sample_path("sample_ioc_rich.eml")
    parsed = parse_eml(path)
    iocs = extract_iocs(parsed)

    assert "phish-secure.xyz" in iocs.domains
    assert "beacon-analytics.com" in iocs.domains
    assert "c2-control.net" in iocs.domains
    assert "external-leak.org" in iocs.domains
    assert "external-scam.org" in iocs.domains


def test_body_email_exclusion_of_envelope():
    """Verify body email harvesting strictly excludes envelope addresses (From/To/Cc)."""
    path = get_sample_path("sample_ioc_rich.eml")
    parsed = parse_eml(path)
    iocs = extract_iocs(parsed)

    # Discovered mentioned emails
    assert "whistleblower@external-leak.org" in iocs.emails
    assert "threat-intel@external-scam.org" in iocs.emails

    # Envelope addresses must be EXCLUDED even if mentioned in body
    assert "sender@alert-sec.com" not in iocs.emails
    assert "analyst@target.com" not in iocs.emails
    assert "bounce@alert-sec.com" not in iocs.emails


def test_undefang_and_clean_helpers():
    """Verify de-fanging and URL cleaning utility functions."""
    assert undefang_text("hxxps[:]//evil[.]com/drop") == "https://evil.com/drop"
    assert undefang_text("hxxp://198.51.100.1[.]2") == "http://198.51.100.1.2"
    assert undefang_text("malware(.)net") == "malware.net"

    # Clean URL handling
    assert clean_url("https://example.com/login.") == "https://example.com/login"
    assert clean_url("javascript:alert(1)") is None
    assert clean_url("mailto:test@example.com") is None
    assert clean_url("https://valid-target.com/page?ref=1#top") is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
