"""
MAVERICK — IP Geolocation & ASN Enrichment Engine (Module 5)
Part of Threat Intelligence (/intel/geo.py)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Union

from maverick.intel.ioc import is_private_ip
from maverick.intel.models import GeoEnrichmentReport, GeoResult, IOCSet
from maverick.parser.models import ParsedEmail

logger = logging.getLogger(__name__)

IP_API_BATCH_URL = "http://ip-api.com/batch"
BATCH_SIZE = 100
DEFAULT_TIMEOUT = 5.0


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP string is a valid public address (not RFC 1918, loopback, or link-local)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        is_priv, _ = is_private_ip(ip_obj)
        return not is_priv
    except ValueError:
        return False


class IPGeoLocator:
    """
    Session-aware IP Geolocation and ASN intelligence provider using ip-api.com.
    
    Key Features:
    - Free-tier batch querying (up to 100 IPs per POST request)
    - Session-level in-memory cache to prevent duplicate lookups
    - Explicit 'inferred_enrichment' evidence labeling and disclaimers
    - Graceful per-IP failure handling on network timeouts or rate limits
    """

    def __init__(self, batch_url: str = IP_API_BATCH_URL, batch_size: int = BATCH_SIZE):
        self.batch_url = batch_url
        self.batch_size = batch_size
        self._cache: Dict[str, GeoResult] = {}
        self._lock = threading.Lock()

    def clear_cache(self) -> None:
        """Clear the in-memory session cache."""
        with self._lock:
            self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Return the current number of cached IP records."""
        with self._lock:
            return len(self._cache)

    def geolocate_ips(
        self,
        ips: List[str],
        timeout: float = DEFAULT_TIMEOUT,
    ) -> GeoEnrichmentReport:
        """
        Geolocate a list of public IP addresses using batch lookups and session caching.
        
        Handles API timeouts, HTTP errors, and individual IP resolution failures
        without failing the overall batch report.
        """
        if not ips:
            return GeoEnrichmentReport(
                results=[],
                total_queried=0,
                cache_hits=0,
                errors_count=0,
            )

        # 1. Deduplicate IPs while preserving order
        unique_ips: List[str] = []
        seen: Set[str] = set()
        for raw_ip in ips:
            clean = str(raw_ip).strip()
            if clean and clean not in seen:
                seen.add(clean)
                unique_ips.append(clean)

        results_map: Dict[str, GeoResult] = {}
        uncached_ips: List[str] = []
        cache_hits = 0

        # 2. Check session cache & pre-validate private IPs
        with self._lock:
            for ip in unique_ips:
                if ip in self._cache:
                    results_map[ip] = self._cache[ip]
                    cache_hits += 1
                elif not is_public_ip(ip):
                    # Flag private/reserved IPs locally without wasting external API quota
                    res = GeoResult(
                        ip=ip,
                        status="fail",
                        error="Private or reserved IP address (not publicly routable)",
                        source="ip-api.com",
                        evidence_type="inferred_enrichment",
                    )
                    self._cache[ip] = res
                    results_map[ip] = res
                else:
                    uncached_ips.append(ip)

        # 3. Query uncached public IPs in batches of up to batch_size
        if uncached_ips:
            for i in range(0, len(uncached_ips), self.batch_size):
                batch = uncached_ips[i : i + self.batch_size]
                batch_results = self._fetch_batch(batch, timeout=timeout)
                with self._lock:
                    for ip, geo_res in batch_results.items():
                        self._cache[ip] = geo_res
                        results_map[ip] = geo_res

        # 4. Assemble final report in original requested order
        ordered_results: List[GeoResult] = [
            results_map.get(ip, GeoResult(ip=ip, status="fail", error="Unresolved"))
            for ip in unique_ips
        ]

        errors_count = sum(1 for r in ordered_results if r.status == "fail")

        return GeoEnrichmentReport(
            results=ordered_results,
            total_queried=len(unique_ips),
            cache_hits=cache_hits,
            errors_count=errors_count,
        )

    def _fetch_batch(self, batch: List[str], timeout: float) -> Dict[str, GeoResult]:
        """Send a single batch POST request to ip-api.com/batch."""
        results: Dict[str, GeoResult] = {}
        payload = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            self.batch_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "MAVERICK-Forensic-Engine/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                data = json.loads(body)

                if isinstance(data, list):
                    for item in data:
                        ip = item.get("query")
                        if not ip:
                            continue
                        status = item.get("status", "fail")
                        if status == "success":
                            results[ip] = GeoResult(
                                ip=ip,
                                country=item.get("country"),
                                country_code=item.get("countryCode"),
                                region=item.get("regionName") or item.get("region"),
                                city=item.get("city"),
                                asn=item.get("as"),
                                isp=item.get("isp") or item.get("org"),
                                status="success",
                                source="ip-api.com",
                                evidence_type="inferred_enrichment",
                                error=None,
                            )
                        else:
                            # ip-api returned status: fail for this individual IP
                            results[ip] = GeoResult(
                                ip=ip,
                                status="fail",
                                error=item.get("message", "IP lookup failed"),
                                source="ip-api.com",
                                evidence_type="inferred_enrichment",
                            )

        except urllib.error.HTTPError as http_err:
            error_msg = f"HTTP {http_err.code}: {http_err.reason}"
            if http_err.code == 429:
                error_msg = "ip-api.com rate limit exceeded (45 req/min)"
            logger.warning("ip-api.com batch lookup error: %s", error_msg)
            for ip in batch:
                if ip not in results:
                    results[ip] = GeoResult(
                        ip=ip,
                        status="fail",
                        error=error_msg,
                        source="ip-api.com",
                        evidence_type="inferred_enrichment",
                    )
        except Exception as exc:
            error_msg = f"Lookup error: {type(exc).__name__} - {str(exc)}"
            logger.warning("ip-api.com batch failure: %s", error_msg)
            for ip in batch:
                if ip not in results:
                    results[ip] = GeoResult(
                        ip=ip,
                        status="fail",
                        error=error_msg,
                        source="ip-api.com",
                        evidence_type="inferred_enrichment",
                    )

        # Ensure all batch IPs have an entry even if ip-api omitted some
        for ip in batch:
            if ip not in results:
                results[ip] = GeoResult(
                    ip=ip,
                    status="fail",
                    error="No response returned by geolocation service",
                    source="ip-api.com",
                    evidence_type="inferred_enrichment",
                )

        return results

    def geolocate_ioc_set(
        self,
        ioc_set: IOCSet,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> GeoEnrichmentReport:
        """
        Geolocate non-excluded, public routable IPs extracted from Module 3's IOCSet.
        Private/RFC 1918 IPs already residing in ioc_set.excluded_ips are skipped.
        """
        public_ips = [
            indicator.ip
            for indicator in ioc_set.ips
            if not indicator.is_private and is_public_ip(indicator.ip)
        ]
        return self.geolocate_ips(public_ips, timeout=timeout)

    def geolocate_parsed_email(
        self,
        parsed_email: ParsedEmail,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> GeoEnrichmentReport:
        """
        Extract IOCs from a ParsedEmail object and geolocate public routable IPs.
        """
        from maverick.intel.ioc import extract_iocs

        ioc_set = extract_iocs(parsed_email)
        return self.geolocate_ioc_set(ioc_set, timeout=timeout)


# Global singleton instance for session-wide caching
_default_geolocator: Optional[IPGeoLocator] = None


def get_geolocator() -> IPGeoLocator:
    """Get or initialize the shared singleton IPGeoLocator instance."""
    global _default_geolocator
    if _default_geolocator is None:
        _default_geolocator = IPGeoLocator()
    return _default_geolocator


def geolocate_ips(
    ips: List[str],
    timeout: float = DEFAULT_TIMEOUT,
) -> GeoEnrichmentReport:
    """Convenience function to geolocate IP addresses using the shared session cache."""
    return get_geolocator().geolocate_ips(ips, timeout=timeout)


def geolocate_ioc_set(
    ioc_set: IOCSet,
    timeout: float = DEFAULT_TIMEOUT,
) -> GeoEnrichmentReport:
    """Convenience function to geolocate public IPs from an IOCSet."""
    return get_geolocator().geolocate_ioc_set(ioc_set, timeout=timeout)


def geolocate_parsed_email(
    parsed_email: ParsedEmail,
    timeout: float = DEFAULT_TIMEOUT,
) -> GeoEnrichmentReport:
    """Convenience function to extract IOCs and geolocate public IPs from a ParsedEmail."""
    return get_geolocator().geolocate_parsed_email(parsed_email, timeout=timeout)


def clear_geo_cache() -> None:
    """Clear the shared session geolocation cache."""
    get_geolocator().clear_cache()
