"""Unit tests for MAVERICK Attachment Static Forensics (Module 6)."""

import io
import os
import sys
import zipfile
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.forensics import (
    AttachmentAnalysisReport,
    AttachmentReport,
    analyze_attachment,
    analyze_email_attachments,
)
from maverick.forensics.analyzer import EICAR_SHA256, EICAR_SIG
from maverick.parser.models import Attachment, ParsedEmail

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_bytes(filename: str) -> bytes:
    path = os.path.normpath(os.path.join(SAMPLES_DIR, filename))
    with open(path, "rb") as f:
        return f.read()


def test_eicar_standard_test_file():
    """Verify EICAR standard anti-malware test signature detection and exact hashes."""
    report = analyze_attachment(
        filename="eicar.com",
        data=EICAR_SIG,
        claimed_type="application/octet-stream",
    )

    assert isinstance(report, AttachmentReport)
    assert report.file_size == 68
    assert report.hashes["sha256"] == EICAR_SHA256
    assert report.hashes["md5"] == "44d88612fea8a8f36de82e1278abb02f"
    assert report.hashes["sha1"] == "3395856ce81f2b7382dee72602f798b642f14140"
    assert report.verdict == "malicious"
    assert any("EICAR" in ind for ind in report.suspicious_indicators)


def test_benign_macro_enabled_document():
    """Verify oletools static extraction detects embedded VBA macros without executing code."""
    data = get_sample_bytes("sample_macro_benign.docx")

    report = analyze_attachment(
        filename="sample_macro_benign.docx",
        data=data,
        claimed_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )

    assert isinstance(report, AttachmentReport)
    assert report.macro_present is True
    assert report.mismatch is False
    assert any("Embedded VBA macros detected" in ind for ind in report.suspicious_indicators)
    assert report.verdict in ("suspicious", "malicious")


def test_disguised_executable_mismatch():
    """Verify executable disguised with .pdf extension is flagged with critical mismatch."""
    # Construct a minimal valid 32-bit DOS/PE stub header
    # Offset 0x00: 'MZ' (DOS Header)
    # Offset 0x3C: Pointer to PE signature (0x80)
    # Offset 0x80: 'PE\x00\x00' followed by minimal COFF file header
    pe_header = bytearray(512)
    pe_header[0:2] = b"MZ"
    pe_header[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
    pe_header[0x80:0x84] = b"PE\x00\x00"
    pe_header[0x84:0x86] = (0x014C).to_bytes(2, byteorder="little")  # i386 machine
    pe_header[0x86:0x88] = (1).to_bytes(2, byteorder="little")       # 1 section
    pe_header[0x94:0x96] = (0xE0).to_bytes(2, byteorder="little")   # size of optional header
    pe_header[0x96:0x98] = (0x0102).to_bytes(2, byteorder="little")  # characteristics: executable 32-bit
    # Optional header magic: 0x10b (PE32)
    pe_header[0x98:0x9A] = (0x010B).to_bytes(2, byteorder="little")

    report = analyze_attachment(
        filename="urgent_invoice.pdf",
        data=bytes(pe_header),
        claimed_type="application/pdf",
    )

    assert report.mismatch is True
    assert "dosexec" in report.detected_mime.lower() or "executable" in report.detected_type.lower()
    assert any("Executable binary disguised" in ind for ind in report.suspicious_indicators)
    assert report.verdict == "malicious"
    assert report.pe_info is not None
    assert report.pe_info.machine in ("IMAGE_FILE_MACHINE_I386", "0x14c", "i386")


def test_zip_archive_double_extension_and_nested_exe():
    """Verify in-memory ZIP inspection flags nested executables and double extensions."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("benign_notes.txt", b"Just meeting notes.")
        zf.writestr("salary_sheet.xlsx.exe", b"MZ fake executable payload")
        zf.writestr("update_helper.vbs", b'MsgBox "Hello"')

    report = analyze_attachment(
        filename="documents.zip",
        data=buf.getvalue(),
        claimed_type="application/zip",
    )

    assert report.archive_info is not None
    assert report.archive_info.total_files == 3
    assert "salary_sheet.xlsx.exe" in report.archive_info.nested_executables
    assert "update_helper.vbs" in report.archive_info.nested_executables
    assert "salary_sheet.xlsx.exe" in report.archive_info.double_extensions
    assert any("double-extension" in ind.lower() for ind in report.suspicious_indicators)
    assert any("nested executable" in ind.lower() for ind in report.suspicious_indicators)
    assert report.verdict == "malicious"


def test_clean_attachment_normal():
    """Verify a clean text attachment is parsed without suspicious indicators."""
    text_data = b"Meeting Agenda:\n1. Threat Forensics\n2. Pipeline Automation"

    report = analyze_attachment(
        filename="agenda.txt",
        data=text_data,
        claimed_type="text/plain",
    )

    assert report.mismatch is False
    assert report.macro_present is None
    assert report.verdict == "clean"
    assert len(report.suspicious_indicators) == 0
    assert report.file_size == len(text_data)
    assert report.hashes["sha256"] != ""


def test_analyze_email_attachments_pipeline():
    """Verify batch attachment analysis from a ParsedEmail object."""
    parsed = ParsedEmail(
        headers={"From": "sender@target.com", "Subject": "Test"},
        body_plain="Please review the attachments.",
        attachments=[
            Attachment(
                filename="clean_memo.txt",
                content_type="text/plain",
                size_bytes=30,
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                raw_bytes=b"Internal corporate memo text.",
            ),
            Attachment(
                filename="eicar_test.com",
                content_type="application/octet-stream",
                size_bytes=68,
                md5="44d88612fea8a8f36de82e1278abb02f",
                sha256=EICAR_SHA256,
                raw_bytes=EICAR_SIG,
            ),
        ],
    )

    analysis = analyze_email_attachments(parsed)
    assert isinstance(analysis, AttachmentAnalysisReport)
    assert analysis.total_attachments == 2
    assert analysis.suspicious_count == 1
    assert "Static analysis only" in analysis.disclaimer

    clean_att = next(a for a in analysis.attachments if a.filename == "clean_memo.txt")
    assert clean_att.verdict == "clean"

    threat_att = next(a for a in analysis.attachments if a.filename == "eicar_test.com")
    assert threat_att.verdict == "malicious"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
