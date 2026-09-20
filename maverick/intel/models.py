"""Data models for MAVERICK Threat Intelligence / IOC Extraction (Module 3)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IPIndicator(BaseModel):
    """Represents an extracted IP address tagged by origin source."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ip: str = Field(description="Normalized IPv4 or IPv6 address")
    source: str = Field(description="Origin source: 'header' (Received/routing) or 'body' (message text)")
    version: int = Field(default=4, description="IP version (4 or 6)")
    is_private: bool = Field(default=False, description="True for RFC 1918, loopback, or link-local subnets")
    notes: Optional[str] = Field(default=None, description="Forensic classification notes (e.g. RFC 1918, Hop #0)")


class URLIndicator(BaseModel):
    """Represents an extracted URL with structural metadata."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    url: str = Field(description="Normalized, de-fanged URL")
    domain: Optional[str] = Field(default=None, description="Extracted host domain / FQDN")
    source: str = Field(default="body_text", description="Extraction source: 'html_href', 'html_src', or 'body_text'")
    is_defanged: bool = Field(default=False, description="True if original URL had security de-fanging (hxxp, [.])")


class IOCSet(BaseModel):
    """
    Structured IOC collection returned by MAVERICK Module 3.
    Contains public routable IOCs and segregated private infrastructure.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ips: List[IPIndicator] = Field(
        default_factory=list,
        description="Actionable public/routable IPs tagged by source ('header' or 'body')"
    )
    urls: List[str] = Field(
        default_factory=list,
        description="De-duplicated URLs extracted from body text and HTML attributes (href, src)"
    )
    domains: List[str] = Field(
        default_factory=list,
        description="Domains extracted from URLs, hostnames, and body email addresses"
    )
    emails: List[str] = Field(
        default_factory=list,
        description="Email addresses mentioned in body text (strictly excluding From/To/Cc envelope headers)"
    )
    excluded_ips: List[IPIndicator] = Field(
        default_factory=list,
        description="RFC 1918, loopback, and link-local private IPs preserved for forensic inspection"
    )

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize IOCSet to standard dictionary."""
        return self.model_dump()


class GeoResult(BaseModel):
    """
    Geolocation and Autonomous System intelligence for an IP address.
    Explicitly categorized as inferred enrichment rather than direct forensic evidence.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ip: str = Field(description="Normalized IP address")
    country: Optional[str] = Field(default=None, description="Country name")
    country_code: Optional[str] = Field(default=None, description="Two-letter ISO country code")
    region: Optional[str] = Field(default=None, description="Region or state name")
    city: Optional[str] = Field(default=None, description="City name")
    asn: Optional[str] = Field(default=None, description="Autonomous System Number and name")
    isp: Optional[str] = Field(default=None, description="Internet Service Provider name")
    source: str = Field(default="ip-api.com", description="Third-party enrichment data source")
    evidence_type: str = Field(
        default="inferred_enrichment",
        description="Forensic qualification: inferred enrichment, not directly observed evidence"
    )
    status: str = Field(default="success", description="Status of lookup: 'success' or 'fail'")
    error: Optional[str] = Field(default=None, description="Failure reason if lookup was unsuccessful")


class GeoEnrichmentReport(BaseModel):
    """
    Aggregated IP geolocation enrichment report.
    Carries explicit disclaimers regarding third-party geolocation databases.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    enrichment_type: str = Field(
        default="inferred_enrichment",
        description="Category of intelligence: inferred enrichment"
    )
    disclaimer: str = Field(
        default="Inferred enrichment - third-party IP geolocation database; not directly observed cryptographic/RFC evidence.",
        description="Forensic evidentiary disclaimer"
    )
    results: List[GeoResult] = Field(
        default_factory=list,
        description="List of geolocated IP results"
    )
    total_queried: int = Field(default=0, description="Total unique IPs requested")
    cache_hits: int = Field(default=0, description="Number of results served from session cache")
    errors_count: int = Field(default=0, description="Number of IPs that encountered resolution errors")

    def to_api_dict(self) -> Dict[str, Any]:
        """Serialize GeoEnrichmentReport to standard dictionary."""
        return self.model_dump()

