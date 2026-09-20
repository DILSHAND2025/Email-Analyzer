"""Data models for MAVERICK Automated Forensic Incident Report (Module 8)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from maverick.fusion.models import ScoreBreakdown


class RecommendationPriority(str, Enum):
    """Priority level for incident response recommendations."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RecommendationCategory(str, Enum):
    """Categorical domain for forensic incident response."""
    IDENTITY_AUTH = "Identity & Authentication"
    MALWARE_ATTACHMENT = "Malware & Attachment"
    NETWORK_FIREWALL = "Network & Firewall"
    CREDENTIAL_USER = "Credential & User Action"
    INCIDENT_RESPONSE = "General Incident Response"


class Recommendation(BaseModel):
    """Actionable remediation recommendation with priority and forensic rationale."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    priority: str = Field(description="Priority: CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    category: str = Field(description="Action domain: Identity, Malware, Network, Credential")
    action: str = Field(description="Concrete operational remediation step")
    rationale: str = Field(description="Evidentiary justification from forensic analysis")


class CaseMetadata(BaseModel):
    """Administrative and chain-of-custody metadata for a forensic investigation."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    case_id: str = Field(description="Unique forensic case identifier (e.g. MAV-20260919-...)")
    generated_at: str = Field(description="ISO 8601 compilation timestamp")
    investigator: str = Field(default="MAVERICK Forensic Engine v1.0", description="Forensic engine / operator identity")
    sha256_eml: Optional[str] = Field(default=None, description="SHA-256 hash of original .eml message bytes")
    platform_version: str = Field(default="MAVERICK 1.0.0", description="Platform release version")


class CaseSummary(BaseModel):
    """High-level summary of parsed RFC 822 email attributes."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    subject: Optional[str] = Field(default=None, description="Email subject")
    from_addr: Optional[str] = Field(default=None, description="Sender From address")
    to_addrs: List[str] = Field(default_factory=list, description="Recipient To addresses")
    date: Optional[str] = Field(default=None, description="Date header string")
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    hops_count: int = Field(default=0, description="Total MTA hops in Received chain")
    attachments_count: int = Field(default=0, description="Total attachments extracted")
    is_multipart: bool = Field(default=False, description="True if MIME multipart")
    forensic_warnings: List[str] = Field(default_factory=list, description="Parsing anomalies")


class ThreatAssessment(BaseModel):
    """Categorical threat evaluation and composite risk scoring."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    verdict: str = Field(description="Verdict: Low, Medium, High, or Critical")
    risk_score: float = Field(description="Normalized overall risk score (0.0000 to 1.0000)")
    threat_indicators_count: int = Field(default=0, description="Total suspicious or malicious indicators flagged")
    summary: str = Field(default="", description="High-level threat narrative")


class TimelineEvent(BaseModel):
    """Chronological MTA hop event in the email transmission lifecycle."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    hop_index: int = Field(description="0-indexed hop in Received chain (0 = earliest originating)")
    timestamp: Optional[str] = Field(default=None, description="Hop timestamp string")
    from_host: Optional[str] = Field(default=None, description="Sending MTA hostname")
    from_ip: Optional[str] = Field(default=None, description="Sending MTA IP address")
    by_host: Optional[str] = Field(default=None, description="Receiving MTA hostname")
    protocol: Optional[str] = Field(default=None, description="Transfer protocol (SMTP, ESMTPS, etc.)")
    delay_seconds: Optional[float] = Field(default=None, description="Transit delay from previous hop in seconds")


class EvidenceFusionSummary(BaseModel):
    """Summary of multi-dimensional evidence fusion scoring."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    contributing_factors: List[str] = Field(default_factory=list)


class ForensicReport(BaseModel):
    """
    Comprehensive Forensic Incident Report for MAVERICK Module 8.
    Provides complete multi-dimensional evidence capture in a single structured object.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    case_metadata: CaseMetadata = Field(description="Case ID and chain of custody metadata")
    case_summary: CaseSummary = Field(description="RFC 822 email metadata summary")
    threat_assessment: ThreatAssessment = Field(description="Threat verdict and overall score")
    evidence_fusion: EvidenceFusionSummary = Field(description="Weighted score breakdown and factors")
    ml_findings: Dict[str, Any] = Field(default_factory=dict, description="ML classification telemetry")
    auth_analysis: Dict[str, Any] = Field(default_factory=dict, description="SPF/DKIM/DMARC status & alignment")
    ioc_evidence: Dict[str, Any] = Field(default_factory=dict, description="Extracted network IOCs & excluded IPs")
    geo_intelligence: Dict[str, Any] = Field(default_factory=dict, description="IP geolocation telemetry & caveat")
    attachment_findings: Dict[str, Any] = Field(default_factory=dict, description="Attachment static forensic findings")
    investigation_timeline: List[TimelineEvent] = Field(default_factory=list, description="Chronological Received hop chain")
    recommendations: List[Recommendation] = Field(default_factory=list, description="Actionable remediation steps")
    pdf_sha256: Optional[str] = Field(default=None, description="SHA-256 hash of the generated PDF file")

    def to_api_dict(self) -> Dict[str, Any]:
        """Convert ForensicReport to standard JSON-serializable dictionary."""
        return self.model_dump()
