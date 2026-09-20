"""
MAVERICK Database Repository & SQLite Engine.
Handles persistence, priority sorting, status updates, and metric telemetry.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from maverick.db.models import Submission

# Default database path: data/maverick.db
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "data", "maverick.db")


def get_db_path(custom_path: Optional[str] = None) -> str:
    """Resolve database path, defaulting to data/maverick.db."""
    if custom_path:
        return custom_path
    env_path = os.environ.get("MAVERICK_DB_PATH")
    return env_path if env_path else DEFAULT_DB_PATH


def init_db(db_path: Optional[str] = None) -> str:
    """Initialize database tables and indexes."""
    target_path = get_db_path(db_path)
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)

    with sqlite3.connect(target_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                upload_timestamp DATETIME NOT NULL,
                case_id TEXT UNIQUE NOT NULL,
                risk_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                full_report_json TEXT NOT NULL,
                pdf_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New'
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_submissions_case_id ON submissions(case_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_submissions_verdict ON submissions(verdict);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_submissions_upload_timestamp ON submissions(upload_timestamp);")
        conn.commit()

    return target_path


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Obtain a SQLite connection with row factory enabled."""
    target_path = get_db_path(db_path)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    return conn


def _parse_timestamp(val: Any) -> datetime:
    """Parse string or datetime into UTC datetime."""
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def create_submission(submission: Submission, db_path: Optional[str] = None) -> Submission:
    """Insert a new email forensic submission."""
    init_db(db_path)
    ts_str = (
        submission.upload_timestamp.isoformat()
        if isinstance(submission.upload_timestamp, datetime)
        else str(submission.upload_timestamp)
    )

    import uuid

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM submissions WHERE case_id = ?", (submission.case_id,))
        if cursor.fetchone():
            suffix = uuid.uuid4().hex[:4].upper()
            submission.case_id = f"{submission.case_id}-{suffix}"
            if "MAVERICK-Report-" in submission.pdf_path:
                d_dir = os.path.dirname(submission.pdf_path)
                submission.pdf_path = os.path.join(d_dir, f"MAVERICK-Report-{submission.case_id}.pdf")

        cursor.execute(
            """
            INSERT INTO submissions (
                filename, upload_timestamp, case_id, risk_score,
                verdict, full_report_json, pdf_path, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                submission.filename,
                ts_str,
                submission.case_id,
                float(submission.risk_score),
                submission.verdict,
                submission.full_report_json,
                submission.pdf_path,
                submission.status,
            ),
        )
        submission.id = cursor.lastrowid
        conn.commit()

    return submission


def get_submission_by_case_id(case_id: str, db_path: Optional[str] = None) -> Optional[Submission]:
    """Retrieve submission record by unique Case ID."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, filename, upload_timestamp, case_id, risk_score,
                   verdict, full_report_json, pdf_path, status
            FROM submissions
            WHERE case_id = ?
            """,
            (case_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        return Submission(
            id=row["id"],
            filename=row["filename"],
            upload_timestamp=_parse_timestamp(row["upload_timestamp"]),
            case_id=row["case_id"],
            risk_score=row["risk_score"],
            verdict=row["verdict"],
            full_report_json=row["full_report_json"],
            pdf_path=row["pdf_path"],
            status=row["status"],
        )


def list_submissions(
    status_filter: Optional[str] = None,
    verdict_filter: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Optional[str] = None,
) -> List[Submission]:
    """
    List submissions sorted by Analyst Priority:
    1. Primary Sort: Verdict severity (Critical -> High -> Medium -> Low)
    2. Secondary Sort: upload_timestamp descending (most recent first within tier)
    """
    init_db(db_path)
    query_parts = ["SELECT id, filename, upload_timestamp, case_id, risk_score, verdict, full_report_json, pdf_path, status FROM submissions WHERE 1=1"]
    params: List[Any] = []

    if status_filter and status_filter.lower() not in ("all", ""):
        query_parts.append("AND LOWER(status) = LOWER(?)")
        params.append(status_filter.strip())

    if verdict_filter and verdict_filter.lower() not in ("all", ""):
        query_parts.append("AND LOWER(verdict) = LOWER(?)")
        params.append(verdict_filter.strip())

    if search and search.strip():
        search_pattern = f"%{search.strip()}%"
        query_parts.append("AND (case_id LIKE ? OR filename LIKE ?)")
        params.extend([search_pattern, search_pattern])

    # Priority sorting order:
    # 1: Critical
    # 2: High
    # 3: Medium
    # 4: Low
    query_parts.append(
        """
        ORDER BY
            CASE UPPER(verdict)
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END ASC,
            upload_timestamp DESC
        LIMIT ? OFFSET ?
        """
    )
    params.extend([limit, offset])

    full_sql = "\n".join(query_parts)
    results: List[Submission] = []

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(full_sql, params)
        rows = cursor.fetchall()
        for r in rows:
            results.append(
                Submission(
                    id=r["id"],
                    filename=r["filename"],
                    upload_timestamp=_parse_timestamp(r["upload_timestamp"]),
                    case_id=r["case_id"],
                    risk_score=r["risk_score"],
                    verdict=r["verdict"],
                    full_report_json=r["full_report_json"],
                    pdf_path=r["pdf_path"],
                    status=r["status"],
                )
            )

    return results


def update_submission_status(case_id: str, new_status: str, db_path: Optional[str] = None) -> Optional[Submission]:
    """Update status for a given Case ID ('New' <-> 'Reviewed')."""
    init_db(db_path)
    clean_status = "Reviewed" if new_status.lower() == "reviewed" else "New"

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE submissions
            SET status = ?
            WHERE case_id = ?
            """,
            (clean_status, case_id),
        )
        conn.commit()

    return get_submission_by_case_id(case_id, db_path)


def count_submissions(db_path: Optional[str] = None) -> Dict[str, int]:
    """Calculate aggregate dashboard statistics."""
    init_db(db_path)
    counts: Dict[str, int] = {
        "total": 0,
        "new": 0,
        "reviewed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN LOWER(status) = 'new' THEN 1 ELSE 0 END) AS count_new,
                SUM(CASE WHEN LOWER(status) = 'reviewed' THEN 1 ELSE 0 END) AS count_reviewed,
                SUM(CASE WHEN LOWER(verdict) = 'critical' THEN 1 ELSE 0 END) AS count_critical,
                SUM(CASE WHEN LOWER(verdict) = 'high' THEN 1 ELSE 0 END) AS count_high,
                SUM(CASE WHEN LOWER(verdict) = 'medium' THEN 1 ELSE 0 END) AS count_medium,
                SUM(CASE WHEN LOWER(verdict) = 'low' THEN 1 ELSE 0 END) AS count_low
            FROM submissions
            """
        )
        row = cursor.fetchone()
        if row:
            counts["total"] = row["total"] or 0
            counts["new"] = row["count_new"] or 0
            counts["reviewed"] = row["count_reviewed"] or 0
            counts["critical"] = row["count_critical"] or 0
            counts["high"] = row["count_high"] or 0
            counts["medium"] = row["count_medium"] or 0
            counts["low"] = row["count_low"] or 0

    return counts


def delete_submission(case_id: str, db_path: Optional[str] = None) -> bool:
    """Delete a submission by Case ID (primarily for test cleanup)."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM submissions WHERE case_id = ?", (case_id,))
        conn.commit()
        return cursor.rowcount > 0
