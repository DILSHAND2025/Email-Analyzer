"""RFC 7601 / RFC 8601 Authentication-Results Header Parser."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

import authres
from maverick.auth.models import AuthStatus, DKIMDetails, DMARCDetails, SPFDetails


def normalize_status(val: Optional[str]) -> str:
    """Normalize status string to lowercase AuthStatus value."""
    if not val:
        return AuthStatus.NONE.value
    clean = val.strip().lower()
    for s in AuthStatus:
        if clean == s.value:
            return s.value
    if "pass" in clean:
        return AuthStatus.PASS.value
    if "fail" in clean:
        return AuthStatus.FAIL.value
    return clean


class AuthenticationResultsParser:
    """Robust parser for Authentication-Results and ARC-Authentication-Results headers."""

    def parse_headers(
        self, headers: List[str]
    ) -> Tuple[
        Optional[SPFDetails],
        List[DKIMDetails],
        Optional[DMARCDetails],
        List[str],
    ]:
        """
        Parse a list of Authentication-Results header values.
        Returns:
            (spf_details, dkim_details_list, dmarc_details, notes)
        """
        notes: List[str] = []
        if not headers:
            return None, [], None, notes

        spf_result: Optional[SPFDetails] = None
        dkim_results: List[DKIMDetails] = []
        dmarc_result: Optional[DMARCDetails] = None

        for idx, raw_hdr in enumerate(headers):
            # Clean header name prefix if present
            clean_hdr = re.sub(r"^(?:Authentication-Results|ARC-Authentication-Results):\s*", "", raw_hdr, flags=re.I).strip()
            if not clean_hdr:
                continue

            parsed_via_authres = False
            try:
                auth_obj = authres.AuthenticationResultsHeader.parse_value(clean_hdr)
                parsed_via_authres = True
                notes.append(f"Header #{idx+1} successfully parsed via standard RFC 8601 authres engine.")

                for item in auth_obj.results:
                    method = getattr(item, "method", "").lower()
                    res_status = normalize_status(getattr(item, "result", None))

                    # Parse all sub-properties (e.g. header.from, smtp.mailfrom, header.d)
                    props_dict: Dict[str, str] = {}
                    for prop in getattr(item, "properties", []):
                        p_type = getattr(prop, "type", "").lower()
                        p_name = getattr(prop, "name", "").lower()
                        p_val = getattr(prop, "value", "")
                        full_key = f"{p_type}.{p_name}" if p_type else p_name
                        props_dict[full_key] = p_val
                        props_dict[p_name] = p_val

                    comment_text = getattr(item, "result_comment", "") or ""

                    if method == "spf":
                        mailfrom = getattr(item, "smtp_mailfrom", None) or props_dict.get("smtp.mailfrom") or props_dict.get("mailfrom")
                        helo = getattr(item, "smtp_helo", None) or props_dict.get("smtp.helo") or props_dict.get("helo")
                        reason = getattr(item, "reason", None) or comment_text
                        spf_result = SPFDetails(
                            status=res_status,
                            domain=mailfrom or (helo if helo and "." in helo else None),
                            helo=helo,
                            reason=reason,
                        )
                    elif method == "dkim":
                        header_d = getattr(item, "header_d", None) or props_dict.get("header.d") or props_dict.get("d")
                        header_s = getattr(item, "header_s", None) or props_dict.get("header.s") or props_dict.get("s")
                        header_i = getattr(item, "header_i", None) or props_dict.get("header.i") or props_dict.get("i")
                        reason = getattr(item, "reason", None) or comment_text
                        d_val = header_d or (header_i.split("@")[-1] if header_i and "@" in header_i else None)
                        dkim_results.append(
                            DKIMDetails(
                                status=res_status,
                                domain=d_val,
                                selector=header_s,
                                identity=header_i,
                                reason=reason,
                            )
                        )
                    elif method == "dmarc":
                        header_from = getattr(item, "header_from", None) or props_dict.get("header.from") or props_dict.get("from")
                        if not header_from:
                            m_hf = re.search(r"header\.from\s*=\s*([^\s;)]+)", clean_hdr)
                            if m_hf:
                                header_from = m_hf.group(1)

                        policy = props_dict.get("p") or props_dict.get("policy")
                        if not policy:
                            m_p = re.search(r"\bp\s*=\s*([a-zA-Z]+)", comment_text)
                            if m_p:
                                policy = m_p.group(1).lower()

                        disposition = props_dict.get("dis") or props_dict.get("disposition")
                        if not disposition:
                            m_dis = re.search(r"\bdis\s*=\s*([a-zA-Z]+)", comment_text)
                            if m_dis:
                                disposition = m_dis.group(1).lower()

                        dmarc_result = DMARCDetails(
                            status=res_status,
                            published_domain=header_from,
                            policy=policy,
                            disposition=disposition,
                            reason=getattr(item, "reason", None) or comment_text,
                        )
            except Exception:
                # Fallback to regex token parsing
                parsed_via_authres = False

            if not parsed_via_authres:
                notes.append(f"Header #{idx+1} used resilient regex fallback parsing.")
                spf_f, dkim_f, dmarc_f = self._parse_with_regex(clean_hdr)
                if spf_f and not spf_result:
                    spf_result = spf_f
                if dkim_f:
                    dkim_results.extend(dkim_f)
                if dmarc_f and not dmarc_result:
                    dmarc_result = dmarc_f

        return spf_result, dkim_results, dmarc_result, notes

    def _parse_with_regex(
        self, text: str
    ) -> Tuple[Optional[SPFDetails], List[DKIMDetails], Optional[DMARCDetails]]:
        """Resilient fallback regex parser for non-standard or malformed headers."""
        spf_details: Optional[SPFDetails] = None
        dkim_details_list: List[DKIMDetails] = []
        dmarc_details: Optional[DMARCDetails] = None

        # 1. Parse SPF
        spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z]+)", text, re.IGNORECASE)
        if spf_match:
            spf_status = normalize_status(spf_match.group(1))
            mailfrom_match = re.search(r"(?:smtp\.mailfrom|domain of)\s*=?\s*<?([^\s;>)]+)", text, re.IGNORECASE)
            mailfrom = mailfrom_match.group(1) if mailfrom_match else None
            helo_match = re.search(r"smtp\.helo\s*=?\s*<?([^\s;>)]+)", text, re.IGNORECASE)
            helo = helo_match.group(1) if helo_match else None
            reason_match = re.search(r"spf=[^;]*\(([^)]+)\)", text, re.IGNORECASE)
            reason = reason_match.group(1).strip() if reason_match else None

            spf_details = SPFDetails(
                status=spf_status,
                domain=mailfrom or helo,
                helo=helo,
                reason=reason,
            )

        # 2. Parse DKIM entries
        for dkim_match in re.finditer(r"\bdkim\s*=\s*([a-zA-Z]+)", text, re.IGNORECASE):
            dkim_status = normalize_status(dkim_match.group(1))
            # Search context around this dkim entry
            start_pos = dkim_match.start()
            clause_slice = text[start_pos : start_pos + 250]
            if ";" in clause_slice:
                clause_slice = clause_slice.split(";", 1)[0]

            d_match = re.search(r"header\.d\s*=\s*([^\s;)]+)", clause_slice, re.IGNORECASE)
            s_match = re.search(r"header\.s\s*=\s*([^\s;)]+)", clause_slice, re.IGNORECASE)
            i_match = re.search(r"header\.i\s*=\s*([^\s;)]+)", clause_slice, re.IGNORECASE)
            domain = d_match.group(1) if d_match else None
            identity = i_match.group(1) if i_match else None
            if not domain and identity and "@" in identity:
                domain = identity.split("@")[-1]

            dkim_details_list.append(
                DKIMDetails(
                    status=dkim_status,
                    domain=domain,
                    selector=s_match.group(1) if s_match else None,
                    identity=identity,
                )
            )

        # 3. Parse DMARC
        dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z]+)", text, re.IGNORECASE)
        if dmarc_match:
            dmarc_status = normalize_status(dmarc_match.group(1))
            from_match = re.search(r"header\.from\s*=\s*([^\s;)]+)", text, re.IGNORECASE)
            policy_match = re.search(r"\bp\s*=\s*([a-zA-Z]+)", text, re.IGNORECASE)
            dis_match = re.search(r"\bdis\s*=\s*([a-zA-Z]+)", text, re.IGNORECASE)

            dmarc_details = DMARCDetails(
                status=dmarc_status,
                published_domain=from_match.group(1) if from_match else None,
                policy=policy_match.group(1).lower() if policy_match else None,
                disposition=dis_match.group(1).lower() if dis_match else None,
            )

        return spf_details, dkim_details_list, dmarc_details
