"""Unit tests for MAVERICK Email Authentication Forensics (Module 2)."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution and IDE analyzers
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.auth import (
    AuthResult,
    EmailAuthAnalyzer,
    analyze_email_auth,
    check_alignment,
    evaluate_domain_alignment,
    extract_domain,
    get_organizational_domain,
)
from maverick.auth.header_parser import AuthenticationResultsParser
from maverick.parser import parse_eml

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_domain_alignment_relaxed_and_strict():
    """Verify RFC 7489 identifier alignment rules for relaxed and strict matching."""
    # 1. Relaxed matching on subdomains (should pass)
    assert check_alignment("mail.corp-defense.com", "corp-defense.com", strict=False) is True
    assert check_alignment("corp-defense.com", "mail.corp-defense.com", strict=False) is True

    # 2. Strict matching on subdomains (must fail)
    assert check_alignment("mail.corp-defense.com", "corp-defense.com", strict=True) is False
    assert check_alignment("corp-defense.com", "corp-defense.com", strict=True) is True

    # 3. Multi-part TLD handling (co.uk)
    assert check_alignment("sub.example.co.uk", "example.co.uk", strict=False) is True
    assert check_alignment("sub.example.co.uk", "other.co.uk", strict=False) is False

    # 4. Completely disparate domains
    assert check_alignment("trusted-bank.com", "compromised-relay.xyz", strict=False) is False
    assert check_alignment("paypal.com", "paypa1.com", strict=False) is False

    # 5. Organizational domain extraction
    assert get_organizational_domain("a.b.c.corp.com") == "corp.com"
    assert get_organizational_domain("mail.amazon.co.uk") == "amazon.co.uk"


def test_auth_results_header_parser():
    """Verify parsing of standard and non-standard Authentication-Results headers."""
    parser = AuthenticationResultsParser()

    raw_header = (
        "mx.google.com; "
        "dkim=pass header.i=@github.com header.s=s20150108; "
        "spf=pass (google.com: domain of noreply@github.com designates 192.30.252.204 as permitted sender) "
        "smtp.mailfrom=noreply@github.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com"
    )

    spf_det, dkim_dets, dmarc_det, notes = parser.parse_headers([raw_header])

    assert spf_det is not None
    assert spf_det.status == "pass"
    assert "github.com" in (spf_det.domain or "")

    assert len(dkim_dets) >= 1
    assert dkim_dets[0].status == "pass"
    assert "github.com" in (dkim_dets[0].domain or "")

    assert dmarc_det is not None
    assert dmarc_det.status == "pass"
    assert dmarc_det.published_domain == "github.com"


def test_auth_pass_and_alignment():
    """Test full analysis on legitimate email with passing auth and aligned domains."""
    path = get_sample_path("sample_auth_pass.eml")
    parsed = parse_eml(path)

    with open(path, "rb") as f:
        raw_bytes = f.read()

    result = analyze_email_auth(parsed, raw_eml_bytes=raw_bytes)

    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.aligned is True
    assert result.spf_aligned is True
    assert result.dkim_aligned is True
    assert result.from_domain == "corp-defense.com"
    assert result.spf_domain == "corp-defense.com"
    assert "corp-defense.com" in result.dkim_domains
    assert result.verification_source == "authentication_results_header"


def test_auth_spoofed_detection():
    """Test spoofed email where From: domain is mismatched with SPF Return-Path."""
    path = get_sample_path("sample_auth_spoofed.eml")
    parsed = parse_eml(path)

    result = analyze_email_auth(parsed)

    # In sample_auth_spoofed:
    # From: security@trusted-bank.com
    # Return-Path: attacker@compromised-relay.xyz
    assert result.from_domain == "trusted-bank.com"
    assert result.spf_domain == "compromised-relay.xyz"
    assert result.spf_aligned is False
    assert result.dkim_aligned is False
    assert result.aligned is False
    assert result.dmarc == "fail"

    # Must include security warning in notes
    notes_blob = " ".join(result.notes)
    assert "SECURITY WARNING" in notes_blob or "mismatch" in notes_blob


def test_fallback_direct_verification():
    """Test fallback to direct verification when Authentication-Results is absent."""
    path = get_sample_path("sample_no_auth_header.eml")
    parsed = parse_eml(path)

    with open(path, "rb") as f:
        raw_bytes = f.read()

    result = analyze_email_auth(parsed, raw_eml_bytes=raw_bytes)

    # Verified source must be direct_verification
    assert result.verification_source == "direct_verification"
    assert result.dkim == "none"  # No DKIM-Signature header present
    assert any("Triggering direct SPF/DKIM verification" in n for n in result.notes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
