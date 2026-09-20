"""Data models for MAVERICK Evidence Fusion Scoring (Module 7)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatVerdict(str, Enum):
    """Categorical threat verdict mapped from the composite risk score."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ScoreBreakdown(BaseModel):
    """Granular sub-score contributions across all forensic dimensions."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ml_phishing: float = Field(default=0.0, description="Weighted contribution from ML phishing probability (max 0.40)")
    authentication: float = Field(default=0.0, description="Weighted contribution from SPF/DKIM/DMARC failures (max 0.20)")
    attachments: float = Field(default=0.0, description="Weighted contribution from attachment static forensics (max 0.20)")
    ioc_geo: float = Field(default=0.0, description="Weighted contribution from IOC and Geolocation reputation signals (max 0.20)")


class FusionResult(BaseModel):
    """
    Composite evidence fusion evaluation for MAVERICK Module 7.
    Produces an actionable risk score, categorical verdict, and executive narrative.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    risk_score: float = Field(description="Normalized overall risk score between 0.0000 and 1.0000")
    verdict: str = Field(description="Actionable verdict: 'Low', 'Medium', 'High', or 'Critical'")
    contributing_factors: List[str] = Field(
        default_factory=list,
        description="Plain-language forensic findings explaining what drove the score"
    )
    score_breakdown: ScoreBreakdown = Field(
        default_factory=ScoreBreakdown,
        description="Breakdown of points contributed by each investigative dimension"
    )
    threat_indicators_count: int = Field(
        default=0,
        description="Total distinct suspicious or malicious indicators flagged across modules"
    )
    summary: str = Field(
        default="",
        description="Concise high-level conclusion for forensic triage reports"
    )
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Detailed nested audit trail from sub-modules (Auth, IOCs, ML, Geo, Attachments)"
    )

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize FusionResult to standard dictionary."""
        return self.model_dump()
