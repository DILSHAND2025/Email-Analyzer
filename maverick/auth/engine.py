"""Forensic Email Authentication Analysis Engine (Module 2)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import re

from maverick.auth.alignment import (
    evaluate_domain_alignment,
    extract_domain,
)
from maverick.auth.direct_verifier import DirectAuthVerifier
from maverick.auth.header_parser import AuthenticationResultsParser
from maverick.auth.models import (
    AuthResult,
    AuthStatus,
    DKIMDetails,
    DMARCDetails,
    SPFDetails,
)
from maverick.parser.models import ParsedEmail


class EmailAuthAnalyzer:
    """Orchestrates SPF, DKIM, DMARC, and domain alignment verification."""

    def __init__(self, fallback_to_direct_verification: bool = True):
        self.fallback_to_direct = fallback_to_direct_verification
        self.header_parser = AuthenticationResultsParser()
        self.direct_verifier = DirectAuthVerifier()

    def analyze(
        self,
        parsed_email: ParsedEmail,
        raw_eml_bytes: Optional[bytes] = None,
        strict_alignment: bool = False,
    ) -> AuthResult:
        """
        Analyze email authentication forensics.
        
        Evaluates Authentication-Results header first. If missing, falls back
        to direct verification via dkimpy and pyspf.
        """
        notes: List[str] = []

        # 1. Determine key domains
        from_domain = extract_domain(parsed_email.from_addr)
        spf_domain = extract_domain(parsed_email.return_path)
        
        # Collect any DKIM domains from DKIM-Signature headers
        dkim_sig_headers = parsed_email.get_headers("DKIM-Signature")
        dkim_domains_from_headers: List[str] = []
        for hdr in dkim_sig_headers:
            d_match = re.search(r"\bd\s*=\s*([^;\s]+)", hdr)
            if d_match:
                dom = extract_domain(d_match.group(1))
                if dom and dom not in dkim_domains_from_headers:
                    dkim_domains_from_headers.append(dom)

        # 2. Check for Authentication-Results / ARC headers
        auth_headers = parsed_email.authentication_results
        spf_details: Optional[SPFDetails] = None
        dkim_details_list: List[DKIMDetails] = []
        dmarc_details: Optional[DMARCDetails] = None
        source = "authentication_results_header"

        if auth_headers:
            notes.append(f"Found {len(auth_headers)} Authentication-Results header(s). Parsing receiver MTA assertions.")
            spf_details, dkim_details_list, dmarc_details, parser_notes = self.header_parser.parse_headers(auth_headers)
            notes.extend(parser_notes)

        # 3. Determine if fallback direct verification is required
        needs_fallback = False
        if not auth_headers:
            needs_fallback = True
            notes.append("No Authentication-Results headers present. Triggering direct SPF/DKIM verification.")
        elif not spf_details and not dkim_details_list:
            needs_fallback = True
            notes.append("Authentication-Results contained no parseable SPF or DKIM records. Running direct verification.")

        if needs_fallback and self.fallback_to_direct:
            source = "direct_verification"
            # Direct DKIM
            dkim_status, direct_dkim_details, dkim_notes = self.direct_verifier.verify_dkim(
                raw_eml_bytes=raw_eml_bytes or b"",
                parsed=parsed_email,
            )
            dkim_details_list.extend(direct_dkim_details)
            notes.extend(dkim_notes)

            # Direct SPF
            spf_status, direct_spf_details, spf_notes = self.direct_verifier.verify_spf(parsed_email)
            if direct_spf_details:
                spf_details = direct_spf_details
            notes.extend(spf_notes)

        # 4. Consolidate primary statuses
        # SPF status
        spf_status = spf_details.status if spf_details else AuthStatus.NONE.value
        if spf_details and spf_details.domain and not spf_domain:
            spf_domain = extract_domain(spf_details.domain)

        # DKIM status & domains
        all_dkim_domains = list(dkim_domains_from_headers)
        for d in dkim_details_list:
            if d.domain:
                c_dom = extract_domain(d.domain)
                if c_dom and c_dom not in all_dkim_domains:
                    all_dkim_domains.append(c_dom)

        if dkim_details_list:
            # If any DKIM signature passed, overall DKIM is pass
            if any(d.status == AuthStatus.PASS.value for d in dkim_details_list):
                dkim_status = AuthStatus.PASS.value
            elif any(d.status == AuthStatus.FAIL.value for d in dkim_details_list):
                dkim_status = AuthStatus.FAIL.value
            else:
                dkim_status = dkim_details_list[0].status
        else:
            dkim_status = AuthStatus.NONE.value

        # 5. Evaluate Domain Alignment (RFC 7489)
        spf_aligned, dkim_aligned, align_notes = evaluate_domain_alignment(
            from_address=parsed_email.from_addr,
            spf_domain=spf_domain,
            dkim_domains=all_dkim_domains,
            strict=strict_alignment,
        )
        notes.extend(align_notes)

        # 6. DMARC status synthesis
        if dmarc_details and dmarc_details.status != AuthStatus.NONE.value:
            dmarc_status = dmarc_details.status
        else:
            # Synthesize DMARC according to RFC 7489:
            # DMARC passes if: (SPF passes AND SPF is aligned) OR (DKIM passes AND DKIM is aligned)
            spf_valid_and_aligned = (spf_status == AuthStatus.PASS.value) and spf_aligned
            dkim_valid_and_aligned = (dkim_status == AuthStatus.PASS.value) and dkim_aligned

            if spf_valid_and_aligned or dkim_valid_and_aligned:
                dmarc_status = AuthStatus.PASS.value
                notes.append("DMARC synthesis: PASS (at least one authenticated mechanism is aligned).")
            elif spf_status in (AuthStatus.FAIL.value, AuthStatus.SOFTFAIL.value) or dkim_status == AuthStatus.FAIL.value:
                dmarc_status = AuthStatus.FAIL.value
                notes.append("DMARC synthesis: FAIL (mechanisms failed or lacked alignment).")
            else:
                dmarc_status = AuthStatus.NONE.value

        # Overall alignment boolean
        overall_aligned = bool(
            (spf_status == AuthStatus.PASS.value and spf_aligned)
            or (dkim_status == AuthStatus.PASS.value and dkim_aligned)
            or (spf_aligned and dkim_aligned)
        )

        # Flag spoofing indicators
        if from_domain and spf_domain and not spf_aligned and not dkim_aligned:
            notes.append(
                f"SECURITY WARNING: Visible From: '{from_domain}' is not aligned with Return-Path/DKIM. "
                "High probability of domain spoofing or unauthorized relay."
            )

        return AuthResult(
            spf=spf_status,
            dkim=dkim_status,
            dmarc=dmarc_status,
            aligned=overall_aligned,
            spf_aligned=spf_aligned,
            dkim_aligned=dkim_aligned,
            from_domain=from_domain,
            spf_domain=spf_domain,
            dkim_domains=all_dkim_domains,
            verification_source=source,
            spf_details=spf_details,
            dkim_details=dkim_details_list,
            dmarc_details=dmarc_details,
            notes=notes,
        )


def analyze_email_auth(
    parsed_email: ParsedEmail,
    raw_eml_bytes: Optional[bytes] = None,
    strict_alignment: bool = False,
) -> AuthResult:
    """Convenience function for Module 2 authentication analysis."""
    analyzer = EmailAuthAnalyzer()
    return analyzer.analyze(
        parsed_email=parsed_email,
        raw_eml_bytes=raw_eml_bytes,
        strict_alignment=strict_alignment,
    )
