"""MAVERICK Evidence Fusion Scoring (Module 7)."""

from maverick.fusion.engine import (
    EvidenceFusionEngine,
    analyze_and_fuse_email,
    fuse_evidence,
    get_fusion_engine,
)
from maverick.fusion.models import (
    FusionResult,
    ScoreBreakdown,
    ThreatVerdict,
)

__all__ = [
    "EvidenceFusionEngine",
    "analyze_and_fuse_email",
    "fuse_evidence",
    "get_fusion_engine",
    "FusionResult",
    "ScoreBreakdown",
    "ThreatVerdict",
]
