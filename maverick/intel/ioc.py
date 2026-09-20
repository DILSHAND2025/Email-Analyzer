"""Threat Intelligence and Indicator of Compromise (IOC) Harvesting Engine (Module 3)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
from bs4 import BeautifulSoup

from maverick.auth.alignment import get_organizational_domain
from maverick.intel.models import IOCSet, IPIndicator, URLIndicator
from maverick.parser.models import ParsedEmail

# Standard IPv4 Regex
IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)

# Email address extraction regex
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", re.IGNORECASE
)

# URL matching regex for plain text
URL_REGEX = re.compile(
    r"(?i)\b(?:https?|hxxps?|ftp)://[^\s<>'\"{}|\\^`\[\]()]+", re.IGNORECASE
)

# Common non-domain file extensions to filter out from domain extraction
NON_DOMAIN_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "7z", "rar", "bin", "exe", "dll",
    "mp3", "mp4", "wav", "avi", "mov", "css", "js", "html", "htm",
}


def undefang_text(text: str) -> str:
    """Un-defang security obfuscated text (e.g. hxxps:// -> https://, [.] -> .)."""
    if not text:
        return ""
    s = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]", ":").replace("(:)", ":")
    s = re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", s)
    s = re.sub(r"(?i)\bhxxp(s?):", r"http\1:", s)
    s = re.sub(r"(?i)\bfxp://", r"ftp://", s)
    return s


def clean_url(url: str) -> Optional[str]:
    """Clean, un-defang, and validate a candidate URL."""
    if not url:
        return None
    url = undefang_text(url.strip())
    # Strip trailing punctuation commonly picked up from sentences
    url = re.sub(r"[\'\"`><\)\].,;:!?]+$", "", url).strip()

    # Filter non-HTTP / irrelevant schemes
    lower = url.lower()
    if lower.startswith(("javascript:", "data:", "tel:", "file:", "#")):
        return None

    if lower.startswith("mailto:"):
        return None

    # Must contain a scheme or valid format
    if not lower.startswith(("http://", "https://", "ftp://")):
        return None

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc or "." not in parsed.netloc and parsed.netloc != "localhost":
            return None
        return url
    except Exception:
        return None


RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def is_private_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if IP address is in private (RFC 1918), loopback, or link-local ranges."""
    if ip_obj.is_loopback:
        return True, "Loopback address (RFC 1122 / RFC 4291)"
    if ip_obj.is_link_local:
        return True, "Link-local subnet (RFC 3927 / RFC 4291)"
    if ip_obj.is_multicast:
        return True, "Multicast address"
    if ip_obj.is_unspecified:
        return True, "Unspecified address (0.0.0.0 / ::)"

    if isinstance(ip_obj, ipaddress.IPv4Address):
        for net in RFC_1918_NETWORKS:
            if ip_obj in net:
                return True, "RFC 1918 / Private subnet"
        # Carrier-grade NAT (100.64.0.0/10)
        cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
        if ip_obj in cgnat_net:
            return True, "Carrier-Grade NAT (RFC 6598)"
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.is_private:
            return True, "IPv6 Unique Local / Private address"

    return False, "Public routable IP"


class IOCHarvester:
    """Extracts and deduplicates network, host, and communication IOCs from an email."""

    def harvest(self, parsed_email: ParsedEmail) -> IOCSet:
        """Harvest all IOCs from headers, plain body, and HTML body."""
        # 1. Harvest and categorize IP addresses
        public_ips, excluded_ips = self._extract_ips(parsed_email)

        # 2. Harvest URLs from HTML attributes and body text
        urls = self._extract_urls(parsed_email)

        # 3. Harvest body email addresses (excluding envelope)
        body_emails = self._extract_body_emails(parsed_email)

        # 4. Harvest domains from URLs and body emails
        domains = self._extract_domains(urls, body_emails)

        return IOCSet(
            ips=public_ips,
            urls=urls,
            domains=domains,
            emails=body_emails,
            excluded_ips=excluded_ips,
        )

    def _extract_ips(
        self, parsed: ParsedEmail
    ) -> Tuple[List[IPIndicator], List[IPIndicator]]:
        """Harvest IPs from Received hops, routing headers, and body text."""
        # Map IP string to dict with source tracking
        discovered_ips: Dict[str, Dict[str, Any]] = {}

        # A. Extract from Received Chain
        for hop in parsed.received_chain:
            if hop.from_ip:
                ip_str = hop.from_ip.strip()
                if ip_str not in discovered_ips:
                    discovered_ips[ip_str] = {
                        "source": "header",
                        "notes": f"Received hop #{hop.hop_index} ({hop.by_host or 'unknown MTA'})",
                    }

        # B. Extract from routing headers (X-Originating-IP, Received-SPF, etc.)
        routing_header_names = ["x-originating-ip", "x-sender-ip", "x-client-ip", "received-spf"]
        for hdr_name in routing_header_names:
            for val in parsed.get_headers(hdr_name):
                for match in IPV4_REGEX.finditer(val):
                    ip_str = match.group(0)
                    if ip_str not in discovered_ips:
                        discovered_ips[ip_str] = {
                            "source": "header",
                            "notes": f"Header: {hdr_name}",
                        }

        # C. Extract from message body (plain text & HTML)
        full_body_text = f"{parsed.body_plain}\n{parsed.body_html}"
        for match in IPV4_REGEX.finditer(full_body_text):
            ip_str = match.group(0)
            if ip_str in discovered_ips:
                # If already discovered in headers, note it also appeared in body
                if "body" not in discovered_ips[ip_str]["source"]:
                    discovered_ips[ip_str]["source"] = "header, body"
            else:
                discovered_ips[ip_str] = {
                    "source": "body",
                    "notes": "Extracted from message body text",
                }

        # Classify IPs into public and excluded (RFC 1918 / loopback)
        public_list: List[IPIndicator] = []
        excluded_list: List[IPIndicator] = []

        for ip_str, meta in discovered_ips.items():
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                is_priv, priv_reason = is_private_ip(ip_obj)

                indicator = IPIndicator(
                    ip=str(ip_obj),
                    source=meta["source"],
                    version=ip_obj.version,
                    is_private=is_priv,
                    notes=f"{priv_reason} | {meta['notes']}" if is_priv else meta["notes"],
                )

                if is_priv:
                    excluded_list.append(indicator)
                else:
                    public_list.append(indicator)
            except ValueError:
                continue

        return public_list, excluded_list

    def _extract_urls(self, parsed: ParsedEmail) -> List[str]:
        """Extract URLs from HTML href/src attributes and plain text with de-fanging support."""
        discovered_urls: List[str] = []
        seen_urls: Set[str] = set()

        def add_url(raw_u: Optional[str]):
            if not raw_u:
                return
            cleaned = clean_url(raw_u)
            if cleaned and cleaned not in seen_urls:
                seen_urls.add(cleaned)
                discovered_urls.append(cleaned)

        # 1. Parse HTML structure via BeautifulSoup
        if parsed.body_html:
            try:
                soup = BeautifulSoup(parsed.body_html, "html.parser")
                # Links
                for a in soup.find_all("a", href=True):
                    add_url(a["href"])
                # Images & media
                for img in soup.find_all("img", src=True):
                    add_url(img["src"])
                # Forms
                for form in soup.find_all("form", action=True):
                    add_url(form["action"])
                # Scripts & iframes
                for elem in soup.find_all(["script", "iframe", "embed", "source"], src=True):
                    add_url(elem["src"])
            except Exception:
                pass

        # 2. Extract from body text using regex (plain text + HTML content)
        combined_text = f"{parsed.body_plain}\n{parsed.body_html}"
        # Also run undefang on the text stream to find de-fanged URLs like hxxps://example[.]com
        for match in URL_REGEX.finditer(combined_text):
            add_url(match.group(0))

        undefanged_stream = undefang_text(combined_text)
        for match in URL_REGEX.finditer(undefanged_stream):
            add_url(match.group(0))

        return discovered_urls

    def _extract_body_emails(self, parsed: ParsedEmail) -> List[str]:
        """Extract email addresses mentioned in body text, excluding envelope addresses."""
        # 1. Gather all envelope email addresses to exclude
        envelope_emails: Set[str] = set()

        def add_envelope(addr_str: Optional[str]):
            if not addr_str:
                return
            for found in EMAIL_REGEX.findall(addr_str):
                envelope_emails.add(found.lower())

        add_envelope(parsed.from_addr)
        add_envelope(parsed.reply_to)
        add_envelope(parsed.return_path)
        for addr in parsed.to_addrs:
            add_envelope(addr)
        for addr in parsed.cc_addrs:
            add_envelope(addr)
        for addr in parsed.bcc_addrs:
            add_envelope(addr)

        # 2. Scan body text for emails
        combined_text = f"{parsed.body_plain}\n{parsed.body_html}"
        # Also check mailto: links in HTML
        if parsed.body_html:
            try:
                soup = BeautifulSoup(parsed.body_html, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.lower().startswith("mailto:"):
                        combined_text += f"\n{href[7:]}"
            except Exception:
                pass

        discovered_emails: List[str] = []
        seen: Set[str] = set()

        for match in EMAIL_REGEX.finditer(combined_text):
            candidate = match.group(0).lower().strip().rstrip(".")
            if candidate not in envelope_emails and candidate not in seen:
                seen.add(candidate)
                discovered_emails.append(candidate)

        return discovered_emails

    def _extract_domains(self, urls: List[str], body_emails: List[str]) -> List[str]:
        """Harvest unique host domains from extracted URLs and mentioned emails."""
        domains: List[str] = []
        seen_domains: Set[str] = set()

        def add_domain(dom_candidate: Optional[str]):
            if not dom_candidate:
                return
            dom = dom_candidate.lower().strip().rstrip(".")
            # Strip port if present
            if ":" in dom:
                dom = dom.split(":")[0]
            # Strip leading brackets or wildcards
            dom = dom.lstrip("*.[")
            # Remove www prefix for canonical domain
            if dom.startswith("www."):
                dom = dom[4:]

            # Validate basic domain format
            if "." in dom and dom != "localhost":
                # Ensure TLD is not an image/file extension
                tld = dom.split(".")[-1]
                if tld not in NON_DOMAIN_EXTENSIONS and len(tld) >= 2:
                    if dom not in seen_domains:
                        seen_domains.add(dom)
                        domains.append(dom)
                    # Also record base organizational domain if distinct
                    org_dom = get_organizational_domain(dom)
                    if org_dom and org_dom != dom and org_dom not in seen_domains:
                        seen_domains.add(org_dom)
                        domains.append(org_dom)

        # 1. From URLs
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.netloc:
                    # Ignore raw IPs
                    netloc_host = parsed.netloc.split(":")[0]
                    try:
                        ipaddress.ip_address(netloc_host)
                    except ValueError:
                        add_domain(netloc_host)
            except Exception:
                pass

        # 2. From body emails
        for email_addr in body_emails:
            if "@" in email_addr:
                add_domain(email_addr.split("@")[-1])

        return domains


def extract_iocs(parsed_email: ParsedEmail) -> IOCSet:
    """Convenience function to harvest and categorize all IOCs from a ParsedEmail object."""
    harvester = IOCHarvester()
    return harvester.harvest(parsed_email)
