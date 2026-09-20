"""Data models for MAVERICK Email Authentication Forensics (Module 2)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuthStatus(str, Enum):
    """Standard authentication results per RFC 7601 / RFC 8601."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class SPFDetails(BaseModel):
    """Granular forensic details for SPF verification."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: str = Field(default=AuthStatus.NONE.value)
    domain: Optional[str] = Field(default=None, description="SPF validated domain (Return-Path / MailFrom)")
    client_ip: Optional[str] = Field(default=None, description="Client MTA IP checked against SPF")
    helo: Optional[str] = Field(default=None, description="HELO / EHLO identity")
    reason: Optional[str] = Field(default=None, description="Explanatory text / diagnostic reason")


class DKIMDetails(BaseModel):
    """Granular forensic details for an individual DKIM signature."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: str = Field(default=AuthStatus.NONE.value)
    domain: Optional[str] = Field(default=None, description="DKIM signing domain (d=)")
    selector: Optional[str] = Field(default=None, description="DKIM key selector (s=)")
    identity: Optional[str] = Field(default=None, description="AUID identity (i=)")
    reason: Optional[str] = Field(default=None, description="Validation diagnostic reason")


class DMARCDetails(BaseModel):
    """Granular forensic details for DMARC evaluation."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: str = Field(default=AuthStatus.NONE.value)
    policy: Optional[str] = Field(default=None, description="Published domain policy: none, quarantine, reject")
    subdomain_policy: Optional[str] = Field(default=None, description="Published subdomain policy (sp=)")
    disposition: Optional[str] = Field(default=None, description="Applied message disposition")
    published_domain: Optional[str] = Field(default=None, description="Domain where DMARC TXT record was discovered")


class AuthResult(BaseModel):
    """
    Forensic authentication evaluation output for MAVERICK Module 2.
    Downstream threat scoring and report generators consume this model.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    spf: str = Field(description="Primary SPF status: pass, fail, softfail, neutral, none, temperror, permerror")
    dkim: str = Field(description="Primary DKIM status: pass, fail, none, temperror, permerror")
    dmarc: str = Field(description="Primary DMARC status: pass, fail, none, temperror, permerror")
    aligned: bool = Field(description="Overall DMARC alignment (true if either SPF or DKIM is aligned and passing)")
    spf_aligned: bool = Field(default=False, description="True if SPF domain aligns with RFC 5322 From domain")
    dkim_aligned: bool = Field(default=False, description="True if DKIM d= domain aligns with RFC 5322 From domain")
    from_domain: Optional[str] = Field(default=None, description="Extracted domain from visible From header")
    spf_domain: Optional[str] = Field(default=None, description="Return-Path / smtp.mailfrom domain")
    dkim_domains: List[str] = Field(default_factory=list, description="List of domains found in DKIM signatures")
    verification_source: str = Field(
        default="authentication_results_header",
        description="Source of result: 'authentication_results_header' or 'direct_verification'"
    )
    spf_details: Optional[SPFDetails] = Field(default=None, description="Granular SPF metadata")
    dkim_details: List[DKIMDetails] = Field(default_factory=list, description="List of granular DKIM signature results")
    dmarc_details: Optional[DMARCDetails] = Field(default=None, description="Granular DMARC policy metadata")
    notes: List[str] = Field(default_factory=list, description="Forensic audit trail, security notes, and spoofing flags")

    def to_api_dict(self) -> Dict[str, Any]:
        """Convert AuthResult to standard dictionary."""
        return self.model_dump()
