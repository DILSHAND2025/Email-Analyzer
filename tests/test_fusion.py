"""Unit tests for MAVERICK Evidence Fusion Scoring (Module 7)."""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.auth.models import AuthResult
from maverick.forensics.analyzer import EICAR_SIG
from maverick.forensics.models import AttachmentAnalysisReport, AttachmentReport
from maverick.fusion import (
    EvidenceFusionEngine,
    FusionResult,
    ScoreBreakdown,
    ThreatVerdict,
    analyze_and_fuse_email,
    fuse_evidence,
    get_fusion_engine,
)
from maverick.intel.models import GeoEnrichmentReport, GeoResult, IOCSet, IPIndicator
from maverick.ml.models import InfluentialTerm, MLClassificationResult
from maverick.parser import parse_eml
from maverick.parser.models import Attachment, ParsedEmail

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_fusion_scoring_weights_and_bounds():
    """Verify exact mathematical weight distribution: 40% ML, 20% Auth, 20% Att, 20% IOC/Geo."""
    engine = EvidenceFusionEngine()

    # 1. Zero risk across all dimensions
    res_zero = engine.fuse()
    assert res_zero.risk_score == 0.0
    assert res_zero.verdict == ThreatVerdict.LOW.value
    assert res_zero.score_breakdown.ml_phishing == 0.0
    assert res_zero.score_breakdown.authentication == 0.0
    assert res_zero.score_breakdown.attachments == 0.0
    assert res_zero.score_breakdown.ioc_geo == 0.0

    # 2. Maximum ML risk only (1.0 * 40% = 0.40)
    ml_max = MLClassificationResult(
        phishing_probability=1.0,
        predicted_label="phishing",
        confidence=1.0,
        top_influential_terms=[InfluentialTerm(term="click", weight=5.0, tfidf=0.5, impact=2.5, indicator="PHISHING")],
    )
    res_ml = engine.fuse(ml_result=ml_max)
    assert res_ml.score_breakdown.ml_phishing == 0.40
    assert res_ml.risk_score == 0.40
    assert res_ml.verdict == ThreatVerdict.MEDIUM.value

    # 3. Maximum Auth failure only (1.0 * 20% = 0.20)
    auth_max = AuthResult(
        spf="fail",
        dkim="fail",
        dmarc="fail",
        aligned=False,
        from_domain="target.com",
    )
    res_auth = engine.fuse(auth_result=auth_max)
    assert res_auth.score_breakdown.authentication == 0.20
    assert res_auth.risk_score == 0.20
    assert res_auth.verdict == ThreatVerdict.LOW.value

    # 4. Maximum Attachment risk only (1.0 * 20% = 0.20)
    att_max = [
        AttachmentReport(
            filename="malware.exe",
            file_size=1024,
            claimed_type="application/pdf",
            detected_type="PE executable",
            detected_mime="application/x-dosexec",
            mismatch=True,
            verdict="malicious",
        )
    ]
    res_att = engine.fuse(attachment_report=att_max)
    assert res_att.score_breakdown.attachments == 0.20
    assert res_att.risk_score == 0.20

    # 5. Maximum IOC risk only (1.0 * 20% = 0.20)
    ioc_max = IOCSet(
        urls=["http://198.51.100.45/login.php", "https://phish.xyz/account"],
        domains=["phish.xyz", "bad.top"],
    )
    res_ioc = engine.fuse(ioc_set=ioc_max)
    assert res_ioc.score_breakdown.ioc_geo == 0.20
    assert res_ioc.risk_score == 0.20

    # 6. Combined maximum across all four dimensions
    res_all_max = engine.fuse(
        auth_result=auth_max,
        ioc_set=ioc_max,
        ml_result=ml_max,
        attachment_report=att_max,
    )
    assert res_all_max.risk_score == 1.0000
    assert res_all_max.verdict == ThreatVerdict.CRITICAL.value


def test_verdict_threshold_mapping():
    """Verify verdict mapping boundaries: Low (<0.3), Medium (0.3-0.6), High (0.6-0.85), Critical (>0.85)."""
    engine = EvidenceFusionEngine()

    assert engine._map_verdict(0.0) == "Low"
    assert engine._map_verdict(0.299) == "Low"
    assert engine._map_verdict(0.300) == "Medium"
    assert engine._map_verdict(0.599) == "Medium"
    assert engine._map_verdict(0.600) == "High"
    assert engine._map_verdict(0.850) == "High"
    assert engine._map_verdict(0.851) == "Critical"
    assert engine._map_verdict(1.000) == "Critical"


def test_clean_benign_email_fusion():
    """Verify clean email produces Low verdict with safe contributing factors."""
    parsed = parse_eml(get_sample_path("sample_clean.eml"))
    result = analyze_and_fuse_email(parsed, include_details=True)

    assert isinstance(result, FusionResult)
    assert result.risk_score < 0.30
    assert result.verdict == "Low"
    assert any("legitimate/benign" in f.lower() for f in result.contributing_factors)
    assert result.details is not None
    assert "auth" in result.details
    assert "ml" in result.details


def test_spoofed_auth_email_fusion():
    """Verify spoofed email triggers authentication failure factor and elevates risk."""
    parsed = parse_eml(get_sample_path("sample_auth_spoofed.eml"))
    result = analyze_and_fuse_email(parsed, include_details=False)

    assert result.score_breakdown.authentication > 0.05
    assert any("Authentication:" in f for f in result.contributing_factors)
    assert any("misalignment" in f.lower() or "dmarc" in f.lower() for f in result.contributing_factors)


def test_critical_phishing_email_fusion():
    """Verify high phishing text + IOC anomalies triggers Critical or High verdict."""
    parsed = parse_eml(get_sample_path("sample_phishing.eml"))
    result = analyze_and_fuse_email(parsed, include_details=True)

    # sample_phishing.eml has ~0.98 ML probability and .xyz domain
    assert result.risk_score >= 0.40
    assert result.verdict in ("Medium", "High", "Critical")
    assert result.score_breakdown.ml_phishing >= 0.35
    assert any("Machine Learning: High confidence phishing" in f for f in result.contributing_factors)


def test_critical_composite_with_malicious_attachment():
    """Verify multi-threat email combining ML phishing, auth fail, and disguised executable achieves Critical verdict (>0.85)."""
    pe_stub = bytearray(512)
    pe_stub[0:2] = b"MZ"
    pe_stub[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    pe_stub[0x80:0x84] = b"PE\x00\x00"
    pe_stub[0x84:0x86] = (0x014C).to_bytes(2, byteorder="little")
    pe_stub[0x86:0x88] = (1).to_bytes(2, byteorder="little")
    pe_stub[0x94:0x96] = (0xE0).to_bytes(2, byteorder="little")
    pe_stub[0x96:0x98] = (0x0102).to_bytes(2, byteorder="little")

    parsed = ParsedEmail(
        headers={
            "From": "Security Desk <alert@spoofed-bank.com>",
            "Return-Path": "<attacker@evil-relay.xyz>",
            "Authentication-Results": "mx.corp.com; spf=fail; dkim=fail; dmarc=fail;",
            "Subject": "URGENT: Suspended Account Notice",
        },
        from_addr="alert@spoofed-bank.com",
        authentication_results=["mx.corp.com; spf=fail; dkim=fail; dmarc=fail;"],
        body_plain=(
            "URGENT NOTICE: Your account is suspended. Click immediately to restore: "
            "http://198.51.100.99/verify or visit https://evil-phish.xyz/login. Claim your money refund now."
        ),
        attachments=[
            Attachment(
                filename="document.pdf",
                content_type="application/pdf",
                size_bytes=len(pe_stub),
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                raw_bytes=bytes(pe_stub),
            )
        ],
    )

    result = analyze_and_fuse_email(parsed, include_details=True)

    # ML (~0.40) + Auth (0.20) + Attachment (0.20) + IOC/IP URL (0.09) > 0.85
    assert result.risk_score > 0.85
    assert result.verdict == "Critical"
    assert result.threat_indicators_count >= 3
    assert len(result.contributing_factors) >= 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
