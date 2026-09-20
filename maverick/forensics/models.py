"""Data models for MAVERICK Attachment Static Forensics (Module 6)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Hashes(BaseModel):
    """Cryptographic hashes calculated for an attachment payload."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    md5: str = Field(description="MD5 hex digest")
    sha1: str = Field(description="SHA-1 hex digest")
    sha256: str = Field(description="SHA-256 hex digest")


class PEHeaderInfo(BaseModel):
    """Static metadata extracted from a Windows Portable Executable (PE) header."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    machine: Optional[str] = Field(default=None, description="Target machine architecture (e.g. AMD64, i386)")
    compile_timestamp: Optional[str] = Field(default=None, description="PE header TimeDateStamp")
    entry_point: Optional[str] = Field(default=None, description="Hex address of code entry point")
    number_of_sections: int = Field(default=0, description="Total number of PE sections")
    section_names: List[str] = Field(default_factory=list, description="List of section names (.text, .data, etc.)")
    subsystem: Optional[str] = Field(default=None, description="PE Subsystem (e.g. GUI, Console)")
    is_packed: bool = Field(default=False, description="Flagged if high entropy or packing indicators detected")


class ArchiveInfo(BaseModel):
    """Static metadata from archive container inspection without extracting to disk."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    total_files: int = Field(default=0, description="Total files contained in archive")
    file_names: List[str] = Field(default_factory=list, description="Manifest of file paths inside archive")
    nested_executables: List[str] = Field(default_factory=list, description="Executable or script files nested in archive")
    double_extensions: List[str] = Field(default_factory=list, description="Files with disguised double extensions (e.g. doc.exe)")
    has_suspicious_paths: bool = Field(default=False, description="Path traversal attempts (e.g. ../) detected")


class AttachmentReport(BaseModel):
    """
    Forensic report for an individual attachment.
    All data produced purely via static analysis without file execution.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    filename: str = Field(description="Attachment filename")
    file_size: int = Field(default=0, description="Payload size in bytes")
    hashes: Dict[str, str] = Field(default_factory=dict, description="MD5, SHA-1, SHA-256 digests")
    claimed_type: str = Field(description="Claimed MIME type from email header")
    detected_type: str = Field(description="Human-readable file type description from magic bytes")
    detected_mime: str = Field(description="Actual MIME type detected from magic bytes")
    mismatch: bool = Field(default=False, description="True if claimed type or extension contradicts detected magic bytes")
    macro_present: Optional[bool] = Field(default=None, description="True if embedded VBA macros found in Office documents")
    suspicious_indicators: List[str] = Field(default_factory=list, description="Actionable threat findings")
    pe_info: Optional[PEHeaderInfo] = Field(default=None, description="PE header info if executable")
    archive_info: Optional[ArchiveInfo] = Field(default=None, description="Archive manifest if ZIP container")
    verdict: str = Field(default="clean", description="Forensic verdict: 'clean', 'suspicious', or 'malicious'")

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize AttachmentReport to dictionary."""
        return self.model_dump()


class AttachmentAnalysisReport(BaseModel):
    """Aggregated forensic report across all attachments in an email."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    total_attachments: int = Field(default=0, description="Total attachments analyzed")
    suspicious_count: int = Field(default=0, description="Number of attachments with suspicious or malicious indicators")
    attachments: List[AttachmentReport] = Field(default_factory=list, description="Individual attachment reports")
    analysis_type: str = Field(default="static_forensics", description="Execution profile: static forensics only")
    disclaimer: str = Field(
        default="Static analysis only: files were analyzed purely in-memory without runtime execution.",
        description="Forensic safety assertion"
    )

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize AttachmentAnalysisReport to dictionary."""
        return self.model_dump()
