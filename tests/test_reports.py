"""Unit tests for MAVERICK Forensic Incident Reports (Module 8)."""

import hashlib
import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.auth.models import AuthResult
from maverick.forensics.models import AttachmentReport
from maverick.fusion.models import FusionResult, ScoreBreakdown
from maverick.intel.models import IOCSet
from maverick.ml.models import InfluentialTerm, MLClassificationResult
from maverick.parser import parse_eml
from maverick.parser.models import Attachment, ParsedEmail
from maverick.reports import (
    ForensicReport,
    build_forensic_report,
    generate_case_id,
    generate_full_report,
    generate_pdf_report,
    generate_recommendations,
    run_full_pipeline_and_generate_report,
)

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_case_id_generation():
    """Verify Case ID follows MAV-YYYYMMDD-HHMMSS-{8_HEX} format and is content-deterministic when bytes provided."""
    cid1 = generate_case_id(email_bytes=b"Sample Email Payload 1")
    cid2 = generate_case_id(email_bytes=b"Sample Email Payload 1")
    cid3 = generate_case_id(email_bytes=b"Different Email Payload")

    assert cid1.startswith("MAV-")
    parts = cid1.split("-")
    assert len(parts) == 4
    # Date part YYYYMMDD
    assert len(parts[1]) == 8
    # Time part HHMMSS
    assert len(parts[2]) == 6
    # Hash digest part
    assert len(parts[3]) == 8
    # Digest is identical when same content hash is provided
    assert parts[3] == cid2.split("-")[3]
    assert parts[3] != cid3.split("-")[3]


def test_recommendations_engine_remediation_rules():
    """Verify recommendation generation maps threat findings to specific remediation actions."""
    # 1. Critical Phishing + Auth Failure + Malicious Disguised Binary
    fusion = FusionResult(
        risk_score=0.95,
        verdict="Critical",
        contributing_factors=["Phishing detected", "Auth failed"],
        threat_indicators_count=4,
        score_breakdown=ScoreBreakdown(ml_phishing=0.38, authentication=0.20, attachments=0.20, ioc_geo=0.17),
    )
    auth = AuthResult(
        spf="fail",
        dkim="fail",
        dmarc="fail",
        aligned=False,
        from_domain="target-bank.com",
    )
    ml = MLClassificationResult(
        phishing_probability=0.98,
        predicted_label="phishing",
        confidence=0.98,
        top_influential_terms=[InfluentialTerm(term="password", weight=5.0, tfidf=0.8, impact=4.0, indicator="PHISHING")],
    )
    att = [
        AttachmentReport(
            filename="trojan.pdf",
            file_size=1024,
            claimed_type="application/pdf",
            detected_type="PE executable",
            detected_mime="application/x-dosexec",
            mismatch=True,
            verdict="malicious",
            hashes={"sha256": "abcdef1234567890"},
        )
    ]
    iocs = IOCSet(urls=["http://198.51.100.22/login"], domains=["evil-relay.xyz"])

    recs = generate_recommendations(
        fusion_result=fusion,
        auth_result=auth,
        ml_result=ml,
        attachment_report=att,
        ioc_set=iocs,
    )

    priorities = [r.priority for r in recs]
    categories = [r.category for r in recs]
    actions_text = " ".join([r.action for r in recs])

    assert "CRITICAL" in priorities
    assert "Identity & Authentication" in categories
    assert "Malware & Attachment" in categories
    assert "Credential & User Action" in categories
    assert "Network & Firewall" in categories
    assert "quarantine" in actions_text.lower()
    assert "password reset" in actions_text.lower()
    assert "edr" in actions_text.lower()


def test_pdf_report_compilation_and_sha256_integrity():
    """Verify PDF compilation, valid binary stream (%PDF-), and exact SHA-256 integrity match."""
    eml_path = get_sample_path("sample_phishing.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    report, pdf_bytes = run_full_pipeline_and_generate_report(eml_bytes)

    # 1. Structure assertions
    assert isinstance(report, ForensicReport)
    assert report.case_metadata.case_id.startswith("MAV-")
    assert report.case_summary.subject is not None
    assert report.threat_assessment.verdict in ("Medium", "High", "Critical")

    # 2. PDF assertions
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")

    # 3. Cryptographic integrity assertion
    computed_hash = hashlib.sha256(pdf_bytes).hexdigest()
    assert report.pdf_sha256 == computed_hash


def test_parallel_json_export_completeness():
    """Verify parallel JSON export contains all 10 forensic sections and serializes cleanly."""
    eml_path = get_sample_path("sample_clean.eml")
    with open(eml_path, "rb") as f:
        eml_bytes = f.read()

    report, pdf_bytes = run_full_pipeline_and_generate_report(eml_bytes)
    json_dict = report.to_api_dict()

    # Verify all expected primary sections
    expected_keys = {
        "case_metadata",
        "case_summary",
        "threat_assessment",
        "evidence_fusion",
        "ml_findings",
        "auth_analysis",
        "ioc_evidence",
        "geo_intelligence",
        "attachment_findings",
        "investigation_timeline",
        "recommendations",
        "pdf_sha256",
    }
    assert expected_keys.issubset(set(json_dict.keys()))

    # Verify nested metadata
    assert json_dict["case_metadata"]["case_id"] == report.case_metadata.case_id
    assert json_dict["threat_assessment"]["verdict"] == "Low"
    assert json_dict["threat_assessment"]["risk_score"] < 0.30
    assert len(json_dict["recommendations"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
