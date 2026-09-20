"""Unit tests for MAVERICK Database Repository and Submission Model."""

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from maverick.db import (
    Submission,
    count_submissions,
    create_submission,
    delete_submission,
    get_submission_by_case_id,
    init_db,
    list_submissions,
    update_submission_status,
)


@pytest.fixture
def temp_db():
    """Provide an isolated temporary database for test execution."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def test_init_db_creates_tables(temp_db):
    """Verify tables and indices are created cleanly."""
    path = init_db(temp_db)
    assert os.path.exists(path)


def test_create_and_get_submission(temp_db):
    """Verify insertion and retrieval of full submission record."""
    sub = Submission(
        filename="suspicious_payroll.eml",
        case_id="MAV-20260920-100000-TEST0001",
        risk_score=0.88,
        verdict="High",
        full_report_json='{"threat_assessment": {"verdict": "High", "risk_score": 0.88}}',
        pdf_path="data/reports/MAVERICK-Report-TEST0001.pdf",
        status="New",
    )

    created = create_submission(sub, db_path=temp_db)
    assert created.id is not None
    assert created.id > 0

    fetched = get_submission_by_case_id("MAV-20260920-100000-TEST0001", db_path=temp_db)
    assert fetched is not None
    assert fetched.filename == "suspicious_payroll.eml"
    assert fetched.case_id == "MAV-20260920-100000-TEST0001"
    assert fetched.risk_score == 0.88
    assert fetched.verdict == "High"
    assert fetched.status == "New"
    assert fetched.pdf_path == "data/reports/MAVERICK-Report-TEST0001.pdf"

    # Verify dictionary serialization with parsed JSON
    d = fetched.to_dict()
    assert d["case_id"] == "MAV-20260920-100000-TEST0001"
    assert isinstance(d["full_report_json"], dict)
    assert d["full_report_json"]["threat_assessment"]["verdict"] == "High"


def test_priority_sorting(temp_db):
    """
    Verify submissions are ordered strictly by priority:
    1. Critical -> High -> Medium -> Low
    2. Newer upload timestamps before older ones within the same verdict
    """
    now = datetime.now(timezone.utc)

    # Insert items out of order
    items = [
        ("low_old.eml", "CASE-LOW-1", 0.12, "Low", now - timedelta(hours=3)),
        ("critical_old.eml", "CASE-CRIT-1", 0.95, "Critical", now - timedelta(hours=2)),
        ("medium.eml", "CASE-MED-1", 0.45, "Medium", now - timedelta(hours=1)),
        ("critical_new.eml", "CASE-CRIT-2", 0.99, "Critical", now),
        ("high.eml", "CASE-HIGH-1", 0.72, "High", now - timedelta(minutes=30)),
        ("low_new.eml", "CASE-LOW-2", 0.05, "Low", now),
    ]

    for fn, cid, score, verdict, ts in items:
        create_submission(
            Submission(
                filename=fn,
                case_id=cid,
                risk_score=score,
                verdict=verdict,
                full_report_json="{}",
                pdf_path=f"data/{cid}.pdf",
                upload_timestamp=ts,
            ),
            db_path=temp_db,
        )

    results = list_submissions(db_path=temp_db)
    result_case_ids = [r.case_id for r in results]

    expected_order = [
        "CASE-CRIT-2",  # Critical (newer)
        "CASE-CRIT-1",  # Critical (older)
        "CASE-HIGH-1",  # High
        "CASE-MED-1",   # Medium
        "CASE-LOW-2",   # Low (newer)
        "CASE-LOW-1",   # Low (older)
    ]

    assert result_case_ids == expected_order


def test_filtering_and_search(temp_db):
    """Verify status filter, verdict filter, and text search."""
    create_submission(
        Submission(
            filename="urgent_wire.eml",
            case_id="MAV-WIRE-01",
            risk_score=0.91,
            verdict="Critical",
            full_report_json="{}",
            pdf_path="data/p1.pdf",
            status="New",
        ),
        db_path=temp_db,
    )
    create_submission(
        Submission(
            filename="clean_memo.eml",
            case_id="MAV-MEMO-02",
            risk_score=0.08,
            verdict="Low",
            full_report_json="{}",
            pdf_path="data/p2.pdf",
            status="Reviewed",
        ),
        db_path=temp_db,
    )

    # Filter status: New
    new_items = list_submissions(status_filter="New", db_path=temp_db)
    assert len(new_items) == 1
    assert new_items[0].case_id == "MAV-WIRE-01"

    # Filter status: Reviewed
    reviewed_items = list_submissions(status_filter="Reviewed", db_path=temp_db)
    assert len(reviewed_items) == 1
    assert reviewed_items[0].case_id == "MAV-MEMO-02"

    # Filter verdict: Critical
    crit_items = list_submissions(verdict_filter="Critical", db_path=temp_db)
    assert len(crit_items) == 1
    assert crit_items[0].case_id == "MAV-WIRE-01"

    # Search by filename
    search_wire = list_submissions(search="wire", db_path=temp_db)
    assert len(search_wire) == 1
    assert search_wire[0].filename == "urgent_wire.eml"

    # Search by Case ID
    search_cid = list_submissions(search="MEMO", db_path=temp_db)
    assert len(search_cid) == 1
    assert search_cid[0].case_id == "MAV-MEMO-02"


def test_status_update(temp_db):
    """Verify analyst toggling status from New to Reviewed and back."""
    create_submission(
        Submission(
            filename="phish.eml",
            case_id="MAV-STATUS-TEST",
            risk_score=0.85,
            verdict="High",
            full_report_json="{}",
            pdf_path="data/p.pdf",
            status="New",
        ),
        db_path=temp_db,
    )

    updated = update_submission_status("MAV-STATUS-TEST", "Reviewed", db_path=temp_db)
    assert updated is not None
    assert updated.status == "Reviewed"

    reverted = update_submission_status("MAV-STATUS-TEST", "New", db_path=temp_db)
    assert reverted is not None
    assert reverted.status == "New"


def test_count_submissions(temp_db):
    """Verify aggregated metrics calculation."""
    items = [
        ("Critical", "New"),
        ("Critical", "Reviewed"),
        ("High", "New"),
        ("Medium", "New"),
        ("Low", "Reviewed"),
    ]
    for idx, (v, s) in enumerate(items):
        create_submission(
            Submission(
                filename=f"file_{idx}.eml",
                case_id=f"CASE-{idx}",
                risk_score=0.5,
                verdict=v,
                full_report_json="{}",
                pdf_path=f"data/{idx}.pdf",
                status=s,
            ),
            db_path=temp_db,
        )

    stats = count_submissions(db_path=temp_db)
    assert stats["total"] == 5
    assert stats["new"] == 3
    assert stats["reviewed"] == 2
    assert stats["critical"] == 2
    assert stats["high"] == 1
    assert stats["medium"] == 1
    assert stats["low"] == 1


def test_delete_submission(temp_db):
    """Verify deletion of record."""
    create_submission(
        Submission(
            filename="del.eml",
            case_id="CASE-DEL",
            risk_score=0.1,
            verdict="Low",
            full_report_json="{}",
            pdf_path="data/del.pdf",
        ),
        db_path=temp_db,
    )

    assert get_submission_by_case_id("CASE-DEL", db_path=temp_db) is not None
    assert delete_submission("CASE-DEL", db_path=temp_db) is True
    assert get_submission_by_case_id("CASE-DEL", db_path=temp_db) is None
