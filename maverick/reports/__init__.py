"""
MAVERICK Forensic Reports Package (Module 8).
Automated forensic report generation in PDF and JSON with SHA-256 integrity verification.
"""

from maverick.reports.generator import (
    build_forensic_report,
    generate_case_id,
    generate_full_report,
    generate_pdf_report,
    run_full_pipeline_and_generate_report,
)
from maverick.reports.models import (
    CaseMetadata,
    CaseSummary,
    EvidenceFusionSummary,
    ForensicReport,
    Recommendation,
    RecommendationCategory,
    RecommendationPriority,
    ThreatAssessment,
    TimelineEvent,
)
from maverick.reports.pdf_builder import ForensicPDFBuilder
from maverick.reports.recommendations import generate_recommendations

__all__ = [
    "CaseMetadata",
    "CaseSummary",
    "EvidenceFusionSummary",
    "ForensicReport",
    "Recommendation",
    "RecommendationCategory",
    "RecommendationPriority",
    "ThreatAssessment",
    "TimelineEvent",
    "ForensicPDFBuilder",
    "generate_case_id",
    "build_forensic_report",
    "generate_pdf_report",
    "generate_full_report",
    "run_full_pipeline_and_generate_report",
    "generate_recommendations",
]
