"""Direct SPF and DKIM verifier using dkimpy and pyspf for fallback analysis."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import dkim
import spf

from maverick.auth.models import AuthStatus, DKIMDetails, SPFDetails
from maverick.parser.models import ParsedEmail


class DirectAuthVerifier:
    """Performs direct cryptographic and DNS authentication checks when headers are absent."""

    def verify_dkim(
        self, raw_eml_bytes: bytes, parsed: ParsedEmail
    ) -> Tuple[str, List[DKIMDetails], List[str]]:
        """
        Verify DKIM signatures directly using dkimpy.
        Returns:
            (primary_status, dkim_details_list, notes)
        """
        notes: List[str] = []
        dkim_headers = parsed.get_headers("DKIM-Signature")
        if not dkim_headers:
            notes.append("Direct DKIM verification: No 'DKIM-Signature' header present on email.")
            return AuthStatus.NONE.value, [], notes

        # Parse selector and domain from DKIM-Signature headers
        details_list: List[DKIMDetails] = []
        passed_any = False

        for idx, sig_header in enumerate(dkim_headers):
            d_match = re.search(r"\bd\s*=\s*([^;\s]+)", sig_header)
            s_match = re.search(r"\bs\s*=\s*([^;\s]+)", sig_header)
            domain = d_match.group(1).strip() if d_match else None
            selector = s_match.group(1).strip() if s_match else None

            details = DKIMDetails(
                domain=domain,
                selector=selector,
                status=AuthStatus.NONE.value,
            )
            details_list.append(details)

        # Attempt verification on raw bytes if provided
        if not raw_eml_bytes:
            notes.append("Direct DKIM verification: Raw EML byte stream unavailable for signature verification.")
            return AuthStatus.NONE.value, details_list, notes

        try:
            is_valid = dkim.verify(raw_eml_bytes)
            if is_valid:
                primary_status = AuthStatus.PASS.value
                notes.append("Direct DKIM verification: Cryptographic signature verified successfully via dkimpy.")
                for det in details_list:
                    det.status = AuthStatus.PASS.value
            else:
                primary_status = AuthStatus.FAIL.value
                notes.append("Direct DKIM verification: Signature verification failed (hash or key mismatch).")
                for det in details_list:
                    det.status = AuthStatus.FAIL.value
        except Exception as exc:
            primary_status = AuthStatus.TEMPERROR.value
            notes.append(f"Direct DKIM verification error: {type(exc).__name__}: {exc}")
            for det in details_list:
                det.status = AuthStatus.TEMPERROR.value
                det.reason = str(exc)

        return primary_status, details_list, notes

    def verify_spf(
        self, parsed: ParsedEmail
    ) -> Tuple[str, Optional[SPFDetails], List[str]]:
        """
        Verify SPF record directly using pyspf against the earliest hop in the Received chain.
        Returns:
            (primary_status, spf_details, notes)
        """
        notes: List[str] = []

        # 1. Determine Sender IP
        sender_ip: Optional[str] = None
        helo: Optional[str] = None

        if parsed.received_chain:
            # Hop 0 is the originating client / relay hop in chronological order
            origin_hop = parsed.received_chain[0]
            sender_ip = origin_hop.from_ip
            helo = origin_hop.from_host or "localhost"

        if not sender_ip:
            notes.append("Direct SPF verification: Could not extract client IP from Received hop chain.")
            return AuthStatus.NONE.value, None, notes

        # 2. Determine Envelope Sender
        sender_address = parsed.return_path or parsed.from_addr or ""
        sender_address = re.sub(r"[<>]", "", sender_address).strip()
        if not sender_address:
            notes.append("Direct SPF verification: Missing sender address (Return-Path and From are empty).")
            return AuthStatus.NONE.value, None, notes

        # Extract sender domain
        sender_domain = sender_address.split("@")[-1] if "@" in sender_address else sender_address

        try:
            # spf.check2 returns (result, code, explanation) or (result, explanation)
            spf_output = spf.check2(i=sender_ip, s=sender_address, h=helo or sender_domain)
            result_status = spf_output[0].lower()
            explanation = spf_output[1] if len(spf_output) > 1 else None

            details = SPFDetails(
                status=result_status,
                domain=sender_domain,
                client_ip=sender_ip,
                helo=helo,
                reason=str(explanation) if explanation else None,
            )
            notes.append(f"Direct SPF verification via pyspf: status='{result_status}' for IP '{sender_ip}'.")
            return result_status, details, notes
        except Exception as exc:
            notes.append(f"Direct SPF verification encountered DNS/network error: {exc}")
            details = SPFDetails(
                status=AuthStatus.TEMPERROR.value,
                domain=sender_domain,
                client_ip=sender_ip,
                helo=helo,
                reason=str(exc),
            )
            return AuthStatus.TEMPERROR.value, details, notes
