"""Domain extraction and RFC 7489 DMARC Identifier Alignment Engine."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# Common multi-part public suffixes for organizational domain extraction
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "web.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "edu.sg", "gov.sg",
}


def extract_domain(address_or_domain: Optional[str]) -> Optional[str]:
    """Extract clean domain name from an email address or host/domain string."""
    if not address_or_domain:
        return None
    val = address_or_domain.strip().lower()

    # Extract inside angle brackets if present
    bracket_match = re.search(r"<([^>]+)>", val)
    if bracket_match:
        val = bracket_match.group(1).strip()

    # Extract part after '@'
    if "@" in val:
        val = val.split("@", 1)[1].strip()

    # Remove any port, trailing dots, or paths
    val = val.split(":")[0].rstrip(".")
    # Remove leading '@' or brackets
    val = val.lstrip("@[]() ")

    # Validate basic domain structure
    if "." not in val and val != "localhost":
        return val if val else None

    return val if val else None


def get_organizational_domain(domain: Optional[str]) -> Optional[str]:
    """
    Extract the organizational (root) domain per RFC 7489 section 3.2.
    e.g.:
      'mail.example.com' -> 'example.com'
      'corp.sub.example.co.uk' -> 'example.co.uk'
      'example.com' -> 'example.com'
    """
    if not domain:
        return None
    dom = extract_domain(domain)
    if not dom:
        return None

    parts = dom.split(".")
    if len(parts) <= 2:
        return dom

    # Check against known multi-part suffixes (e.g. co.uk, com.au)
    two_part_suffix = f"{parts[-2]}.{parts[-1]}"
    if two_part_suffix in MULTI_PART_TLDS:
        if len(parts) >= 3:
            return ".".join(parts[-3:])
        return dom

    # Default single TLD (e.g. example.com from sub.example.com)
    return ".".join(parts[-2:])


def check_alignment(
    domain_a: Optional[str],
    domain_b: Optional[str],
    strict: bool = False,
) -> bool:
    """
    Check if two domains align according to RFC 7489.
    
    strict=False (Relaxed): Returns True if their organizational domains match.
    strict=True (Strict): Returns True only if their FQDNs match exactly.
    """
    if not domain_a or not domain_b:
        return False

    norm_a = extract_domain(domain_a)
    norm_b = extract_domain(domain_b)

    if not norm_a or not norm_b:
        return False

    if strict:
        return norm_a == norm_b

    # Relaxed alignment: compare organizational domains
    org_a = get_organizational_domain(norm_a)
    org_b = get_organizational_domain(norm_b)
    return bool(org_a and org_b and org_a == org_b)


def evaluate_domain_alignment(
    from_address: Optional[str],
    spf_domain: Optional[str],
    dkim_domains: List[str],
    strict: bool = False,
) -> Tuple[bool, bool, List[str]]:
    """
    Evaluate SPF and DKIM identifier alignment against RFC 5322 From: domain.
    
    Returns:
      (spf_aligned: bool, dkim_aligned: bool, forensic_notes: list[str])
    """
    notes: List[str] = []
    from_dom = extract_domain(from_address)
    spf_dom = extract_domain(spf_domain)
    
    clean_dkim_domains = [extract_domain(d) for d in dkim_domains if extract_domain(d)]

    if not from_dom:
        notes.append("Alignment warning: RFC 5322 From: domain could not be determined.")
        return False, False, notes

    # 1. Evaluate SPF Alignment
    spf_aligned = False
    if spf_dom:
        spf_aligned = check_alignment(from_dom, spf_dom, strict=strict)
        if spf_aligned:
            alignment_type = "strict (exact FQDN)" if strict else "relaxed (organizational domain)"
            notes.append(f"SPF domain '{spf_dom}' aligns with From: domain '{from_dom}' ({alignment_type}).")
        else:
            notes.append(
                f"SPF alignment mismatch: Return-Path/MailFrom '{spf_dom}' does not match From: '{from_dom}'."
            )
    else:
        notes.append("SPF alignment note: No SPF Return-Path / MailFrom domain found to compare.")

    # 2. Evaluate DKIM Alignment
    dkim_aligned = False
    if clean_dkim_domains:
        for d_dom in clean_dkim_domains:
            if check_alignment(from_dom, d_dom, strict=strict):
                dkim_aligned = True
                alignment_type = "strict (exact FQDN)" if strict else "relaxed (organizational domain)"
                notes.append(f"DKIM signing domain '{d_dom}' aligns with From: domain '{from_dom}' ({alignment_type}).")
                break
        if not dkim_aligned:
            notes.append(
                f"DKIM alignment mismatch: None of the DKIM domains ({', '.join(clean_dkim_domains)}) "
                f"align with From: domain '{from_dom}'."
            )
    else:
        notes.append("DKIM alignment note: No DKIM signing domains available for alignment check.")

    return spf_aligned, dkim_aligned, notes
