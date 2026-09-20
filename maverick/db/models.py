"""
MAVERICK Database Models for Email Threat Submissions.
Provides schema definitions compatible with both SQLAlchemy and native SQLite.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Check if SQLAlchemy is installed
try:
    from sqlalchemy import Column, DateTime, Float, Integer, String, Text
    from sqlalchemy.orm import declarative_base

    Base = declarative_base()
    HAS_SQLALCHEMY = True

    class SubmissionModel(Base):  # type: ignore[valid-type, misc]
        """SQLAlchemy ORM Model for submissions table."""
        __tablename__ = "submissions"

        id = Column(Integer, primary_key=True, autoincrement=True)
        filename = Column(String(255), nullable=False)
        upload_timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
        case_id = Column(String(64), unique=True, nullable=False, index=True)
        risk_score = Column(Float, nullable=False)
        verdict = Column(String(32), nullable=False)
        full_report_json = Column(Text, nullable=False)
        pdf_path = Column(String(512), nullable=False)
        status = Column(String(32), nullable=False, default="New")

        def to_dict(self, parse_json: bool = True) -> Dict[str, Any]:
            report_data: Any = self.full_report_json
            if parse_json and isinstance(self.full_report_json, str):
                try:
                    report_data = json.loads(self.full_report_json)
                except Exception:
                    report_data = {}
            return {
                "id": self.id,
                "filename": self.filename,
                "upload_timestamp": (
                    self.upload_timestamp.isoformat()
                    if isinstance(self.upload_timestamp, datetime)
                    else str(self.upload_timestamp)
                ),
                "case_id": self.case_id,
                "risk_score": float(self.risk_score),
                "verdict": self.verdict,
                "full_report_json": report_data,
                "pdf_path": self.pdf_path,
                "status": self.status,
            }

except ImportError:
    HAS_SQLALCHEMY = False
    Base = None  # type: ignore[assignment, misc]
    SubmissionModel = None  # type: ignore[assignment, misc]


@dataclass
class Submission:
    """Standardized representation of an email forensic submission."""
    filename: str
    case_id: str
    risk_score: float
    verdict: str
    full_report_json: str  # Serialized JSON string
    pdf_path: str
    upload_timestamp: Optional[datetime] = None
    status: str = "New"
    id: Optional[int] = None

    def __post_init__(self) -> None:
        if self.upload_timestamp is None:
            self.upload_timestamp = datetime.now(timezone.utc)

    def to_dict(self, parse_json: bool = True) -> Dict[str, Any]:
        report_data: Any = self.full_report_json
        if parse_json and isinstance(self.full_report_json, str):
            try:
                report_data = json.loads(self.full_report_json)
            except Exception:
                report_data = {}
        return {
            "id": self.id,
            "filename": self.filename,
            "upload_timestamp": (
                self.upload_timestamp.isoformat()
                if isinstance(self.upload_timestamp, datetime)
                else str(self.upload_timestamp)
            ),
            "case_id": self.case_id,
            "risk_score": round(float(self.risk_score), 4),
            "verdict": self.verdict,
            "full_report_json": report_data,
            "pdf_path": self.pdf_path,
            "status": self.status,
        }
