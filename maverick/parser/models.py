"""Data models for MAVERICK Forensic EML/MIME Parser."""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, ConfigDict, Field


class ReceivedHop(BaseModel):
    """Represents a single parsed hop in the email's Received header chain."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    hop_index: int = Field(description="Hop index (0 = earliest originating hop in chain)")
    raw: str = Field(description="Full raw Received header line")
    from_host: Optional[str] = Field(default=None, description="Reported sending hostname / domain")
    from_ip: Optional[str] = Field(default=None, description="Extracted sender IP (IPv4 or IPv6)")
    by_host: Optional[str] = Field(default=None, description="Receiving MTA hostname / domain")
    with_protocol: Optional[str] = Field(default=None, description="Transfer protocol (e.g. SMTP, ESMTPS)")
    id: Optional[str] = Field(default=None, description="MTA queue ID / transaction ID")
    for_recipient: Optional[str] = Field(default=None, description="Envelope recipient recorded by MTA")
    timestamp_raw: Optional[str] = Field(default=None, description="Raw date string from header")
    timestamp: Optional[datetime] = Field(default=None, description="Parsed timezone-aware datetime")
    delay_seconds: Optional[float] = Field(
        default=None,
        description="Transit delay in seconds relative to preceding hop (hop_index - 1)"
    )


class Attachment(BaseModel):
    """Represents an extracted email attachment or inline media asset."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    filename: str = Field(description="Sanitized and decoded filename")
    content_type: str = Field(description="MIME Content-Type (e.g. application/pdf, image/png)")
    content_disposition: str = Field(default="attachment", description="MIME disposition: attachment, inline, etc.")
    content_id: Optional[str] = Field(default=None, description="Content-ID header for inline referencing")
    size_bytes: int = Field(description="Payload size in bytes")
    md5: str = Field(description="Hex MD5 digest for threat intelligence matching")
    sha256: str = Field(description="Hex SHA256 digest for threat intelligence matching")
    raw_bytes: bytes = Field(default=b"", repr=False, description="Raw binary content in memory")
    content_base64: Optional[str] = Field(default=None, description="Base64 encoded content for API transmission")

    def to_api_dict(self, include_bytes: bool = False) -> Dict[str, Any]:
        """Convert attachment to dictionary for API serialization."""
        data = {
            "filename": self.filename,
            "content_type": self.content_type,
            "content_disposition": self.content_disposition,
            "content_id": self.content_id,
            "size_bytes": self.size_bytes,
            "md5": self.md5,
            "sha256": self.sha256,
        }
        if include_bytes:
            data["content_base64"] = self.content_base64 or base64.b64encode(self.raw_bytes).decode("ascii")
        return data


class ParsedEmail(BaseModel):
    """The central structured object produced by Module 1 that downstream modules consume."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    headers: Dict[str, Union[str, List[str]]] = Field(
        default_factory=dict,
        description="Case-preserved dictionary of headers. Multiple occurrences stored as lists."
    )
    raw_headers: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="Exact sequence of (Header-Name, Header-Value) as parsed from the MIME stream."
    )
    subject: Optional[str] = Field(default=None, description="Decoded email Subject")
    from_addr: Optional[str] = Field(default=None, description="Sender address from From header")
    to_addrs: List[str] = Field(default_factory=list, description="List of recipient addresses from To header")
    cc_addrs: List[str] = Field(default_factory=list, description="List of CC recipient addresses")
    bcc_addrs: List[str] = Field(default_factory=list, description="List of BCC recipient addresses")
    reply_to: Optional[str] = Field(default=None, description="Reply-To address if provided")
    return_path: Optional[str] = Field(default=None, description="Return-Path envelope address")
    date: Optional[str] = Field(default=None, description="Raw Date header string")
    date_parsed: Optional[datetime] = Field(default=None, description="Parsed ISO datetime of email Date header")
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    authentication_results: List[str] = Field(
        default_factory=list,
        description="Authentication-Results and ARC-Authentication-Results headers"
    )
    body_plain: str = Field(default="", description="Extracted plain text body parts concatenated")
    body_html: str = Field(default="", description="Extracted HTML body parts concatenated")
    attachments: List[Attachment] = Field(default_factory=list, description="List of extracted attachments")
    received_chain: List[ReceivedHop] = Field(
        default_factory=list,
        description="Ordered list of MTA hops (hop 0 = originating hop, ascending towards destination)"
    )
    is_multipart: bool = Field(default=False, description="True if email is MIME multipart")
    has_attachments: bool = Field(default=False, description="True if email contains one or more attachments")
    forensic_warnings: List[str] = Field(
        default_factory=list,
        description="Forensic anomalies detected during parsing (missing headers, corrupt hops, boundary errors)"
    )

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Case-insensitive single header lookup. If header had multiple values, returns the first."""
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                if isinstance(v, list):
                    return v[0] if v else default
                return v
        return default

    def get_headers(self, name: str) -> List[str]:
        """Case-insensitive multi-header lookup. Always returns a list."""
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                if isinstance(v, list):
                    return v
                return [v]
        return []

    def to_api_dict(self, include_attachment_bytes: bool = False) -> Dict[str, Any]:
        """Convert ParsedEmail to a clean JSON-serializable dictionary."""
        data = self.model_dump(exclude={"attachments", "raw_headers"})
        data["date_parsed"] = self.date_parsed.isoformat() if self.date_parsed else None
        
        # Serialize received hops with ISO formatted dates
        serialized_hops = []
        for hop in self.received_chain:
            h_dict = hop.model_dump()
            h_dict["timestamp"] = hop.timestamp.isoformat() if hop.timestamp else None
            serialized_hops.append(h_dict)
        data["received_chain"] = serialized_hops

        # Serialize attachments
        data["attachments"] = [
            att.to_api_dict(include_bytes=include_attachment_bytes)
            for att in self.attachments
        ]
        return data
