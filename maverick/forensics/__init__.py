"""MAVERICK Attachment Static Forensics (Module 6)."""

from maverick.forensics.analyzer import (
    AttachmentAnalyzer,
    analyze_attachment,
    analyze_email_attachments,
    get_analyzer,
)
from maverick.forensics.models import (
    ArchiveInfo,
    AttachmentAnalysisReport,
    AttachmentReport,
    Hashes,
    PEHeaderInfo,
)

__all__ = [
    "AttachmentAnalyzer",
    "analyze_attachment",
    "analyze_email_attachments",
    "get_analyzer",
    "Hashes",
    "PEHeaderInfo",
    "ArchiveInfo",
    "AttachmentReport",
    "AttachmentAnalysisReport",
]
