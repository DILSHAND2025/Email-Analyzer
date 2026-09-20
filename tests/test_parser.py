import os
import sys
from pathlib import Path

# Ensure project root is in sys.path for direct script execution and IDE analyzers
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest

from maverick.parser import parse_eml
from maverick.parser.received import parse_received_header

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def get_sample_path(filename: str) -> str:
    return os.path.normpath(os.path.join(SAMPLES_DIR, filename))


def test_parse_clean_email():
    """Case 1: Fully compliant email with headers, dual body, attachment, and Received chain."""
    path = get_sample_path("sample_clean.eml")
    parsed = parse_eml(path)

    # 1. Headers verification
    assert parsed.subject == "[ALERT] Urgent SOC Investigation Briefing - Ref #9042"
    assert "security-alert@corp-defense.com" in (parsed.from_addr or "")
    assert "analyst@target-corp.internal" in parsed.to_addrs
    assert "irt@target-corp.internal" in parsed.cc_addrs
    assert parsed.message_id == "<20260918101528.9ZzY8712@corp-defense.com>"
    assert parsed.return_path == "<security-alert@corp-defense.com>"
    assert parsed.date_parsed is not None
    assert parsed.date_parsed.year == 2026

    # Authentication-Results
    assert len(parsed.authentication_results) >= 1
    assert "dkim=pass" in parsed.authentication_results[0]
    assert "spf=pass" in parsed.authentication_results[0]

    # Header dictionary multi-value check
    assert "From" in parsed.headers
    assert "Received" in parsed.headers
    assert isinstance(parsed.headers["Received"], list)
    assert len(parsed.headers["Received"]) == 3

    # Case-insensitive helper
    assert parsed.get_header("subject") == "[ALERT] Urgent SOC Investigation Briefing - Ref #9042"
    assert len(parsed.get_headers("received")) == 3

    # 2. Dual body extraction
    assert "Suspicious outbound beaconing activity detected" in parsed.body_plain
    assert "Incident Response Command" in parsed.body_plain
    assert "<h2 style=" in parsed.body_html
    assert "<code>10.20.30.40</code>" in parsed.body_html

    # 3. Attachments verification
    assert parsed.has_attachments is True
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Incident_Report_9042.pdf"
    assert att.content_type == "application/pdf"
    assert att.content_disposition == "attachment"
    assert att.size_bytes > 0
    assert len(att.raw_bytes) == att.size_bytes
    assert len(att.md5) == 32
    assert len(att.sha256) == 64
    assert att.raw_bytes.startswith(b"%PDF")

    # 4. Received chain verification (ordered earliest/origin -> latest/destination)
    assert len(parsed.received_chain) == 3

    # Hop 0: Earliest hop from client to relay-us-east
    hop0 = parsed.received_chain[0]
    assert hop0.hop_index == 0
    assert hop0.from_ip == "10.20.30.40"
    assert hop0.by_host == "relay-us-east.corp-defense.com"
    assert hop0.with_protocol == "ESMTP"
    assert hop0.delay_seconds is None  # Origin has no preceding hop

    # Hop 1: relay-us-east to mx1.target-corp.com
    hop1 = parsed.received_chain[1]
    assert hop1.hop_index == 1
    assert hop1.from_ip == "198.51.100.12"
    assert hop1.from_host == "relay-us-east.corp-defense.com"
    assert hop1.by_host == "mx1.target-corp.com"
    assert hop1.with_protocol == "ESMTPS"
    assert hop1.delay_seconds is not None
    assert hop1.delay_seconds == pytest.approx(4.0, abs=1.0)

    # Hop 2: mx1 to mailserver.target-corp.internal
    hop2 = parsed.received_chain[2]
    assert hop2.hop_index == 2
    assert hop2.from_ip == "198.51.100.25"
    assert hop2.by_host == "mailserver.target-corp.internal"
    assert hop2.delay_seconds is not None
    assert hop2.delay_seconds == pytest.approx(3.0, abs=1.0)


def test_parse_malformed_edge_case():
    """Case 2: Edge-case email with missing headers, broken boundary, and corrupt timestamps."""
    path = get_sample_path("sample_edge_malformed.eml")
    parsed = parse_eml(path)

    # Must not crash!
    assert parsed is not None

    # Missing core headers should be None
    assert parsed.subject is None
    assert parsed.date is None
    assert parsed.date_parsed is None
    assert parsed.message_id is None
    assert parsed.return_path is None

    # From and To addresses are extracted
    assert parsed.from_addr == "spoofed-sender@compromised-host.org"
    assert "victim@company.com" in parsed.to_addrs

    # Forensic warnings must record all detected anomalies
    warnings_text = " ".join(parsed.forensic_warnings)
    assert "Missing 'Message-ID' header" in warnings_text
    assert "Missing 'Date' header" in warnings_text

    # Body extraction should still succeed for text part
    assert "This email has NO Subject" in parsed.body_plain

    # Attachment with missing filename gets sanitized fallback name
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename.startswith("unnamed_attachment_")
    assert att.content_type == "application/octet-stream"
    assert att.size_bytes > 0
    assert b"Hello Maverick malformed test payload!" in att.raw_bytes

    # Received chain: malformed date flagged in warnings, hops still captured
    assert len(parsed.received_chain) == 2
    assert any("timestamp could not be parsed" in w for w in parsed.forensic_warnings)


def test_parse_nested_multipart():
    """Case 3: Deeply nested multipart (mixed > related > alternative) with inline CID and attached .eml."""
    path = get_sample_path("sample_nested_multipart.eml")
    parsed = parse_eml(path)

    # RFC 2047 Decoded subject
    assert parsed.subject == "Fwd: Forensic Investigation: Phishing Evasion Package"

    # Plain and HTML bodies extracted from deep nesting
    assert "Héllo MAVERICK Forensic Team" in parsed.body_plain
    assert "Lead Threat Hunter" in parsed.body_plain
    assert "<img src=\"cid:logo_cid_001@maverick\"" in parsed.body_html

    # Total attachments should include: inline image, forwarded .eml, and PDF
    filenames = [a.filename for a in parsed.attachments]
    assert "shield_logo.png" in filenames
    assert "phishing_sample_forwarded.eml" in filenames
    assert "malicious_macro_analysis.pdf" in filenames

    # Check inline asset
    inline_logo = next(a for a in parsed.attachments if a.filename == "shield_logo.png")
    assert inline_logo.content_disposition == "inline"
    assert inline_logo.content_id == "<logo_cid_001@maverick>"
    assert inline_logo.content_type == "image/png"
    assert len(inline_logo.raw_bytes) > 0

    # Check forwarded message attachment
    fwd_msg = next(a for a in parsed.attachments if a.filename == "phishing_sample_forwarded.eml")
    assert fwd_msg.content_type == "message/rfc822"
    assert b"phisher@spoofed-bank.com" in fwd_msg.raw_bytes

    # Check PDF attachment
    pdf_att = next(a for a in parsed.attachments if a.filename == "malicious_macro_analysis.pdf")
    assert pdf_att.content_type == "application/pdf"
    assert len(pdf_att.sha256) == 64


def test_received_hop_parsing_variations():
    """Case 4: Granular hop parsing across various MTA syntaxes (IPv4, IPv6, missing fields)."""
    # Variation A: Standard Postfix / Exim with bracketed IP
    raw_a = (
        "from mail.attacker.com (mail.attacker.com [198.51.100.42]) "
        "by mx.google.com with ESMTPS id abc123 for <user@victim.com>; "
        "Fri, 18 Sep 2026 12:00:00 +0000"
    )
    hop_a = parse_received_header(raw_a, hop_index=0)
    assert hop_a.from_host == "mail.attacker.com"
    assert hop_a.from_ip == "198.51.100.42"
    assert hop_a.by_host == "mx.google.com"
    assert hop_a.with_protocol == "ESMTPS"
    assert hop_a.id == "abc123"
    assert hop_a.for_recipient == "<user@victim.com>"
    assert hop_a.timestamp is not None
    assert hop_a.timestamp.hour == 12

    # Variation B: IPv6 address
    raw_b = (
        "from relay.net ([2001:db8:85a3::8a2e:370:7334]) "
        "by mx.internal.org with SMTP; "
        "Fri, 18 Sep 2026 12:05:00 +0000"
    )
    hop_b = parse_received_header(raw_b, hop_index=1)
    assert hop_b.from_ip == "2001:db8:85a3::8a2e:370:7334"
    assert hop_b.by_host == "mx.internal.org"

    # Variation C: Minimal without "from" clause (common in internal Google / Exchange hops)
    raw_c = "by mail-wm1-f44.google.com with SMTP id 5b1f17b18; Fri, 18 Sep 2026 12:10:00 -0700"
    hop_c = parse_received_header(raw_c, hop_index=2)
    assert hop_c.from_host is None
    assert hop_c.from_ip is None
    assert hop_c.by_host == "mail-wm1-f44.google.com"
    assert hop_c.id == "5b1f17b18"
    assert hop_c.timestamp is not None

    # Variation D: Unparseable garbage string should not raise exceptions
    raw_d = "Garbage data without any standard headers or dates @@$$%%"
    hop_d = parse_received_header(raw_d, hop_index=3)
    assert hop_d.raw == raw_d
    assert hop_d.timestamp is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
