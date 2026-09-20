"""Parser for RFC 5321 / RFC 2822 Received header chains."""

from __future__ import annotations

import re
import ipaddress
from datetime import datetime
from typing import List, Optional, Tuple
from email.utils import parsedate_to_datetime

import dateutil.parser

from maverick.parser.models import ReceivedHop

# Regex patterns for clause extraction
IPV4_PATTERN = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b")
IPV6_PATTERN = re.compile(
    r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|"
    r":(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|"
    r"fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(?:ffff(?::0{1,4}){0,1}:){0,1}"
    r"(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:"
    r"(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    r"(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
)

# Clause keywords in standard Received headers
KEYWORDS = ["from", "by", "with", "id", "for", "via"]


def _clean_string(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    val = re.sub(r"\s+", " ", val).strip()
    return val if val else None


def _extract_ip(text: str) -> Optional[str]:
    """Find the first valid IPv4 or IPv6 in a text snippet."""
    if not text:
        return None

    # 1. Look for [ip] or [IPv6:ip]
    for b in re.findall(r"\[(?:IPv6:)?([a-fA-F0-9:.]+)\]", text):
        cleaned = b.strip()
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            pass

    # 2. Look for IPv4 pattern
    ipv4_match = IPV4_PATTERN.search(text)
    if ipv4_match:
        candidate = ipv4_match.group(0)
        try:
            return str(ipaddress.IPv4Address(candidate))
        except ValueError:
            pass

    # 3. Look for tokens that are valid IPv6
    tokens = re.split(r"[\s\(\)\[\];,]+", text)
    for tok in tokens:
        if ":" in tok and len(tok) >= 3:
            clean_tok = tok.replace("IPv6:", "").strip()
            try:
                return str(ipaddress.IPv6Address(clean_tok))
            except ValueError:
                pass

    return None



def parse_timestamp(date_str: str) -> Optional[datetime]:
    """Attempt to parse date using RFC 2822 parser, falling back to dateutil."""
    if not date_str:
        return None
    date_clean = re.sub(r"\s+", " ", date_str).strip()
    # Strip comments in parentheses if parsedate_to_datetime struggles, e.g. (UTC)
    try:
        return parsedate_to_datetime(date_clean)
    except Exception:
        pass

    # Try removing trailing parenthetical info like (UTC) or (PST)
    cleaned = re.sub(r"\([^)]*\)", "", date_clean).strip()
    try:
        return parsedate_to_datetime(cleaned)
    except Exception:
        pass

    # Fallback to dateutil
    try:
        return dateutil.parser.parse(date_clean)
    except Exception:
        pass

    try:
        return dateutil.parser.parse(cleaned)
    except Exception:
        return None


def parse_received_header(raw_header: str, hop_index: int = 0) -> ReceivedHop:
    """
    Parse an individual Received header into structured hop components.
    
    Standard format:
    from <host> (<auth-and-ip>) by <host> with <proto> id <id> for <recipient>; <timestamp>
    """
    normalized = re.sub(r"\s+", " ", raw_header).strip()

    # Split routing info from timestamp by the last semicolon ';'
    clauses_part = normalized
    timestamp_part: Optional[str] = None

    if ";" in normalized:
        parts = normalized.rsplit(";", 1)
        clauses_part = parts[0].strip()
        timestamp_part = parts[1].strip()

    parsed_time: Optional[datetime] = None
    if timestamp_part:
        parsed_time = parse_timestamp(timestamp_part)

    # Extract clauses: from, by, with, id, for
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    hop_id: Optional[str] = None
    for_recipient: Optional[str] = None

    # Regex matcher for clauses
    clause_regex = re.compile(
        r"\b(from|by|with|id|for|via)\s+((?:(?!\b(?:from|by|with|id|for|via)\b).)+)",
        re.IGNORECASE,
    )

    matches = list(clause_regex.finditer(clauses_part))
    clause_dict: dict[str, str] = {}
    for match in matches:
        key = match.group(1).lower()
        val = match.group(2).strip()
        if key not in clause_dict:
            clause_dict[key] = val

    # 1. From clause
    if "from" in clause_dict:
        raw_from = clause_dict["from"]
        from_ip = _extract_ip(raw_from)
        # Separate the primary host from parentheses/brackets
        # E.g. "mail.example.com (mail.example.com [192.0.2.1])" -> "mail.example.com"
        host_match = re.match(r"^([^\s\(\)\[\]]+)", raw_from)
        if host_match:
            from_host = host_match.group(1)
        else:
            from_host = raw_from

    # 2. By clause
    if "by" in clause_dict:
        raw_by = clause_dict["by"]
        host_match = re.match(r"^([^\s\(\)\[\]]+)", raw_by)
        if host_match:
            by_host = host_match.group(1)
        else:
            by_host = raw_by

    # 3. With clause
    if "with" in clause_dict:
        raw_with = clause_dict["with"]
        with_protocol = raw_with.split()[0] if raw_with else None

    # 4. Id clause
    if "id" in clause_dict:
        raw_id = clause_dict["id"]
        hop_id = raw_id.split()[0] if raw_id else None

    # 5. For clause
    if "for" in clause_dict:
        for_recipient = clause_dict["for"]

    return ReceivedHop(
        hop_index=hop_index,
        raw=normalized,
        from_host=_clean_string(from_host),
        from_ip=from_ip,
        by_host=_clean_string(by_host),
        with_protocol=_clean_string(with_protocol),
        id=_clean_string(hop_id),
        for_recipient=_clean_string(for_recipient),
        timestamp_raw=_clean_string(timestamp_part),
        timestamp=parsed_time,
        delay_seconds=None,  # Computed when building the chain
    )


def parse_received_chain(raw_headers: List[str]) -> Tuple[List[ReceivedHop], List[str]]:
    """
    Parse an email's Received header list into a chronologically ordered hop chain.
    
    Note: In raw emails, the top-most Received header is the last hop (arrival at final destination MTA).
    The bottom-most Received header is the first hop (submission or earliest relay).
    
    This function reverses the raw headers so:
    hop_index 0 = originating hop (earliest)
    hop_index N = final delivery hop (latest)
    
    Also computes transit delay (delay_seconds) between consecutive hops.
    """
    warnings: List[str] = []
    if not raw_headers:
        return [], warnings

    # Reverse to arrange chronologically (origin -> destination)
    ordered_raw = list(reversed(raw_headers))
    hops: List[ReceivedHop] = []

    for idx, raw in enumerate(ordered_raw):
        try:
            hop = parse_received_header(raw, hop_index=idx)
            hops.append(hop)
            if not hop.timestamp:
                warnings.append(f"Hop #{idx} timestamp could not be parsed: '{hop.timestamp_raw or raw}'")
        except Exception as exc:
            warnings.append(f"Failed to parse Received hop #{idx}: {exc}")
            hops.append(ReceivedHop(hop_index=idx, raw=raw))

    # Calculate delay_seconds between consecutive hops if timestamps are valid
    for i in range(1, len(hops)):
        prev_time = hops[i - 1].timestamp
        curr_time = hops[i].timestamp
        if prev_time and curr_time:
            delta = (curr_time - prev_time).total_seconds()
            hops[i].delay_seconds = max(0.0, delta)

    return hops, warnings
