"""
Core Report Generation Engine for MAVERICK (Module 8).
Orchestrates end-to-end evidence synthesis, case ID generation, PDF rendering, and SHA-256 integrity stamping.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from maverick.auth.models import AuthResult
from maverick.forensics.models import AttachmentAnalysisReport, AttachmentReport
from maverick.fusion import fuse_evidence
from maverick.fusion.models import FusionResult
from maverick.intel.models import GeoEnrichmentReport, IOCSet
from maverick.ml.models import MLClassificationResult
from maverick.parser import parse_eml
from maverick.parser.models import ParsedEmail
from maverick.reports.models import (
    CaseMetadata,
    CaseSummary,
    EvidenceFusionSummary,
    ForensicReport,
    ThreatAssessment,
    TimelineEvent,
)
from maverick.reports.pdf_builder import ForensicPDFBuilder
from maverick.reports.recommendations import generate_recommendations


def generate_case_id(
    email_bytes: Optional[bytes] = None,
    subject: Optional[str] = None,
) -> str:
    """
    Generate a unique, forensic case identifier based on timestamp and content hash.
    Format: MAV-YYYYMMDD-HHMMSS-{8_HEX_CHARS}
    """
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y%m%d-%H%M%S")

    if email_bytes:
        digest = hashlib.sha256(email_bytes).hexdigest()[:8].upper()
    elif subject:
        entropy = f"{time.time()}-{subject}".encode("utf-8")
        digest = hashlib.sha256(entropy).hexdigest()[:8].upper()
    else:
        entropy = f"{time.time()}-{time.process_time()}".encode("utf-8")
        digest = hashlib.sha256(entropy).hexdigest()[:8].upper()

    return f"MAV-{ts_str}-{digest}"


def build_forensic_report(
    parsed_email: ParsedEmail,
    auth_result: Optional[AuthResult] = None,
    ioc_set: Optional[IOCSet] = None,
    ml_result: Optional[MLClassificationResult] = None,
    geo_report: Optional[GeoEnrichmentReport] = None,
    attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]] = None,
    fusion_result: Optional[FusionResult] = None,
    raw_eml_bytes: Optional[bytes] = None,
    case_id: Optional[str] = None,
) -> ForensicReport:
    """
    Construct a unified ForensicReport model from sub-module outputs.
    """
    # Ensure fusion result is computed
    if fusion_result is None:
        fusion_result = fuse_evidence(
            auth_result=auth_result,
            ioc_set=ioc_set,
            ml_result=ml_result,
            geo_report=geo_report,
            attachment_report=attachment_report,
        )

    cid = case_id or generate_case_id(email_bytes=raw_eml_bytes, subject=parsed_email.subject)
    now_iso = datetime.now(timezone.utc).isoformat()
    eml_sha256 = hashlib.sha256(raw_eml_bytes).hexdigest() if raw_eml_bytes else None

    # 1. Metadata
    metadata = CaseMetadata(
        case_id=cid,
        generated_at=now_iso,
        investigator="MAVERICK Forensic Engine v1.0",
        sha256_eml=eml_sha256,
        platform_version="MAVERICK 1.0.0",
    )

    # 2. Case Summary
    summary = CaseSummary(
        subject=parsed_email.subject,
        from_addr=parsed_email.from_addr,
        to_addrs=parsed_email.to_addrs,
        date=parsed_email.date,
        message_id=parsed_email.message_id,
        hops_count=len(parsed_email.received_chain),
        attachments_count=len(parsed_email.attachments),
        is_multipart=parsed_email.is_multipart,
        forensic_warnings=parsed_email.forensic_warnings,
    )

    # 3. Threat Assessment
    assessment = ThreatAssessment(
        verdict=fusion_result.verdict,
        risk_score=fusion_result.risk_score,
        threat_indicators_count=fusion_result.threat_indicators_count,
        summary=fusion_result.summary,
    )

    # 4. Evidence Fusion Summary
    fusion_summary = EvidenceFusionSummary(
        score_breakdown=fusion_result.score_breakdown,
        contributing_factors=fusion_result.contributing_factors,
    )

    # 5. Timeline Events
    timeline_events: List[TimelineEvent] = []
    for h in parsed_email.received_chain:
        timeline_events.append(
            TimelineEvent(
                hop_index=h.hop_index,
                timestamp=h.timestamp.isoformat() if h.timestamp else h.timestamp_raw,
                from_host=h.from_host,
                from_ip=h.from_ip,
                by_host=h.by_host,
                protocol=h.with_protocol,
                delay_seconds=h.delay_seconds,
            )
        )

    # 6. Recommendations
    recs = generate_recommendations(
        fusion_result=fusion_result,
        auth_result=auth_result,
        ioc_set=ioc_set,
        ml_result=ml_result,
        geo_report=geo_report,
        attachment_report=attachment_report,
    )

    # Serialize sub-module findings defensively
    def _dump(obj: Any) -> Dict[str, Any]:
        if obj is None:
            return {}
        if hasattr(obj, "to_api_dict"):
            return obj.to_api_dict()
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if isinstance(obj, list):
            return {"items": [_dump(x) for x in obj]}
        return {}

    return ForensicReport(
        case_metadata=metadata,
        case_summary=summary,
        threat_assessment=assessment,
        evidence_fusion=fusion_summary,
        ml_findings=_dump(ml_result),
        auth_analysis=_dump(auth_result),
        ioc_evidence=_dump(ioc_set),
        geo_intelligence=_dump(geo_report),
        attachment_findings=_dump(attachment_report),
        investigation_timeline=timeline_events,
        recommendations=recs,
        pdf_sha256=None,
    )


def generate_pdf_report(report: ForensicReport) -> bytes:
    """Compile ForensicReport into PDF binary bytes."""
    builder = ForensicPDFBuilder()
    return builder.build_pdf(report)


def generate_full_report(
    parsed_email: ParsedEmail,
    auth_result: Optional[AuthResult] = None,
    ioc_set: Optional[IOCSet] = None,
    ml_result: Optional[MLClassificationResult] = None,
    geo_report: Optional[GeoEnrichmentReport] = None,
    attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]] = None,
    fusion_result: Optional[FusionResult] = None,
    raw_eml_bytes: Optional[bytes] = None,
    case_id: Optional[str] = None,
) -> Tuple[ForensicReport, bytes]:
    """
    Build the structured ForensicReport, compile the PDF, compute the PDF SHA-256
    integrity digest, and stamp it on the report model.
    Returns: (ForensicReport, pdf_bytes)
    """
    report = build_forensic_report(
        parsed_email=parsed_email,
        auth_result=auth_result,
        ioc_set=ioc_set,
        ml_result=ml_result,
        geo_report=geo_report,
        attachment_report=attachment_report,
        fusion_result=fusion_result,
        raw_eml_bytes=raw_eml_bytes,
        case_id=case_id,
    )

    # Render PDF
    pdf_bytes = generate_pdf_report(report)

    # Compute PDF integrity digest
    pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    report.pdf_sha256 = pdf_sha256

    return report, pdf_bytes


def run_full_pipeline_and_generate_report(
    raw_eml_bytes: bytes,
    case_id: Optional[str] = None,
) -> Tuple[ForensicReport, bytes]:
    """
    Execute the entire MAVERICK forensic pipeline (Modules 1 through 7)
    and produce the Module 8 Forensic Incident Report and PDF.
    """
    from maverick.auth import analyze_email_auth
    from maverick.forensics import analyze_email_attachments
    from maverick.intel import extract_iocs, geolocate_ioc_set
    from maverick.ml import classify_parsed_email

    # 1. Parse EML
    parsed_email = parse_eml(raw_eml_bytes)

    # 2. Email Auth Forensics
    auth_res = analyze_email_auth(parsed_email)

    # 3. IOC Extraction
    ioc_res = extract_iocs(parsed_email)

    # 4. ML Phishing Inference (classify)
    ml_res = classify_parsed_email(parsed_email)

    # 5. Geolocation Intelligence (geo)
    geo_res = geolocate_ioc_set(ioc_res)

    # 6. Attachment Static Forensics
    att_res = analyze_email_attachments(parsed_email)

    # 7. Evidence Fusion
    fusion_res = fuse_evidence(
        auth_result=auth_res,
        ioc_set=ioc_res,
        ml_result=ml_res,
        geo_report=geo_res,
        attachment_report=att_res,
    )

    # 8. Forensic Report & PDF
    return generate_full_report(
        parsed_email=parsed_email,
        auth_result=auth_res,
        ioc_set=ioc_res,
        ml_result=ml_res,
        geo_report=geo_res,
        attachment_report=att_res,
        fusion_result=fusion_res,
        raw_eml_bytes=raw_eml_bytes,
        case_id=case_id,
    )
