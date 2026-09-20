"""
MAVERICK — Evidence Fusion Scoring Engine (Module 7)
Synthesizes forensic outputs across all modules into a composite risk verdict.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from maverick.auth.models import AuthResult
from maverick.forensics.models import AttachmentAnalysisReport, AttachmentReport
from maverick.fusion.models import FusionResult, ScoreBreakdown, ThreatVerdict
from maverick.intel.models import GeoEnrichmentReport, IOCSet
from maverick.ml.models import MLClassificationResult
from maverick.parser.models import ParsedEmail

logger = logging.getLogger(__name__)

# Heuristic list of suspicious / high-abuse TLDs often seen in phishing & spam
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".work", ".loan",
    ".cam", ".live", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".country", ".stream", ".download", ".racing", ".bid",
}

# Regex to detect URLs hosting directly on IP addresses (e.g. http://192.0.2.1/login)
IP_IN_URL_PATTERN = re.compile(
    r"(?i)https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)"
)


class EvidenceFusionEngine:
    """
    Weighted Evidence Fusion Engine for MAVERICK.
    
    Weights:
    - 40% — ML Phishing Probability
    - 20% — Email Authentication Failures (SPF/DKIM/DMARC / Alignment)
    - 20% — Attachment Risk (MIME mismatch, macros, executables)
    - 20% — Threat Intelligence & Geolocation Reputation Signals
    """

    def fuse(
        self,
        auth_result: Optional[AuthResult] = None,
        ioc_set: Optional[IOCSet] = None,
        ml_result: Optional[MLClassificationResult] = None,
        geo_report: Optional[GeoEnrichmentReport] = None,
        attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]] = None,
    ) -> FusionResult:
        """
        Synthesize multi-source forensic evidence into a weighted composite score and verdict.
        """
        contributing_factors: List[str] = []
        total_threat_indicators = 0

        # 1. Dimension 1: Machine Learning Phishing (40% weight)
        ml_raw_score, ml_factors, ml_threat_count = self._score_ml(ml_result)
        contributing_factors.extend(ml_factors)
        total_threat_indicators += ml_threat_count

        # 2. Dimension 2: Email Authentication Forensics (20% weight)
        auth_raw_score, auth_factors, auth_threat_count = self._score_auth(auth_result)
        contributing_factors.extend(auth_factors)
        total_threat_indicators += auth_threat_count

        # 3. Dimension 3: Attachment Static Forensics (20% weight)
        att_raw_score, att_factors, att_threat_count = self._score_attachments(attachment_report)
        contributing_factors.extend(att_factors)
        total_threat_indicators += att_threat_count

        # 4. Dimension 4: IOC & Geolocation Reputation Signals (20% weight)
        ioc_raw_score, ioc_factors, ioc_threat_count = self._score_ioc_geo(ioc_set, geo_report)
        contributing_factors.extend(ioc_factors)
        total_threat_indicators += ioc_threat_count

        # 5. Composite Weighted Risk Calculation
        w_ml = round(0.40 * ml_raw_score, 4)
        w_auth = round(0.20 * auth_raw_score, 4)
        w_att = round(0.20 * att_raw_score, 4)
        w_ioc = round(0.20 * ioc_raw_score, 4)

        risk_score = round(w_ml + w_auth + w_att + w_ioc, 4)
        risk_score = min(1.0, max(0.0, risk_score))

        # 6. Map to Verdict Thresholds
        verdict = self._map_verdict(risk_score)

        # 7. Summary Narrative
        summary = (
            f"Overall threat assessed as {verdict.upper()} (Risk Score: {risk_score:.2f}/1.00) "
            f"with {total_threat_indicators} suspicious/malicious indicators identified across forensics modules."
        )

        breakdown = ScoreBreakdown(
            ml_phishing=w_ml,
            authentication=w_auth,
            attachments=w_att,
            ioc_geo=w_ioc,
        )

        return FusionResult(
            risk_score=risk_score,
            verdict=verdict,
            contributing_factors=contributing_factors,
            score_breakdown=breakdown,
            threat_indicators_count=total_threat_indicators,
            summary=summary,
        )

    def analyze_and_fuse_email(
        self,
        parsed_email: ParsedEmail,
        include_details: bool = True,
    ) -> FusionResult:
        """
        Execute the entire MAVERICK forensic pipeline (Modules 1 through 6) on an email
        and return the synthesized Evidence Fusion Result.
        """
        from maverick.auth import analyze_email_auth
        from maverick.forensics import analyze_email_attachments
        from maverick.intel import extract_iocs, geolocate_ioc_set
        from maverick.ml import classify_parsed_email

        # 1. Auth check
        auth_res = analyze_email_auth(parsed_email)

        # 2. IOC extraction
        ioc_res = extract_iocs(parsed_email)

        # 3. Geolocation enrichment
        geo_res = geolocate_ioc_set(ioc_res)

        # 4. ML inference
        ml_res = classify_parsed_email(parsed_email)

        # 5. Attachment forensics
        att_res = analyze_email_attachments(parsed_email)

        # 6. Fuse all evidence
        fusion = self.fuse(
            auth_result=auth_res,
            ioc_set=ioc_res,
            ml_result=ml_res,
            geo_report=geo_res,
            attachment_report=att_res,
        )

        if include_details:
            fusion.details = {
                "auth": getattr(auth_res, "to_api_dict", auth_res.model_dump)(),
                "iocs": getattr(ioc_res, "to_api_dict", ioc_res.model_dump)(),
                "geo": getattr(geo_res, "to_api_dict", geo_res.model_dump)(),
                "ml": getattr(ml_res, "to_api_dict", ml_res.model_dump)(),
                "attachments": getattr(att_res, "to_api_dict", att_res.model_dump)(),
            }

        return fusion

    def _score_ml(
        self, ml_result: Optional[MLClassificationResult]
    ) -> Tuple[float, List[str], int]:
        """Evaluate ML phishing probability (40% weight)."""
        if not ml_result:
            return 0.0, ["Machine Learning: No body text available for inference."], 0

        prob = ml_result.phishing_probability
        factors: List[str] = []
        threat_count = 0

        # Extract top terms
        terms = [t.term for t in ml_result.top_influential_terms[:4]]
        terms_str = f" (prominent terms: {', '.join(terms)})" if terms else ""

        if prob >= 0.80:
            threat_count += 2
            factors.append(
                f"Machine Learning: High confidence phishing text detected ({prob*100:.1f}% probability){terms_str}."
            )
        elif prob >= 0.50:
            threat_count += 1
            factors.append(
                f"Machine Learning: Moderate phishing likelihood detected ({prob*100:.1f}% probability){terms_str}."
            )
        else:
            factors.append(
                f"Machine Learning: Message body classified as legitimate/benign ({prob*100:.1f}% phishing probability)."
            )

        return prob, factors, threat_count

    def _score_auth(
        self, auth_result: Optional[AuthResult]
    ) -> Tuple[float, List[str], int]:
        """Evaluate email authentication integrity and domain alignment (20% weight)."""
        if not auth_result:
            return 0.0, ["Authentication: No authentication results or headers available."], 0

        dmarc = auth_result.dmarc.lower()
        spf = auth_result.spf.lower()
        dkim = auth_result.dkim.lower()
        aligned = auth_result.aligned

        points = 0.0
        factors: List[str] = []
        threat_count = 0

        # DMARC Policy evaluation
        if dmarc in ("fail", "permerror"):
            points += 0.50
            threat_count += 1
            factors.append(f"Authentication: DMARC verification failed (status: {dmarc.upper()}).")
        elif dmarc in ("none", "temperror"):
            points += 0.15

        # Domain alignment check
        if not aligned:
            points += 0.35
            threat_count += 1
            from_dom = auth_result.from_domain or "unknown"
            factors.append(
                f"Authentication: Sender identity misalignment detected — From: '{from_dom}' does not align with authenticated SPF or DKIM domains."
            )

        # SPF status
        if spf in ("fail", "permerror"):
            points += 0.25
            threat_count += 1
            factors.append(f"Authentication: SPF policy check failed for sending MTA (status: {spf.upper()}).")
        elif spf == "softfail":
            points += 0.10
            factors.append("Authentication: SPF softfail indicated by sender domain policy.")

        # DKIM status
        if dkim in ("fail", "permerror"):
            points += 0.25
            threat_count += 1
            factors.append("Authentication: DKIM cryptographic signature verification failed.")

        # Clean case
        if points == 0.0 and aligned and dmarc == "pass":
            factors.append("Authentication: Passed all SPF, DKIM, and DMARC alignment checks.")

        raw_score = min(1.0, points)
        return raw_score, factors, threat_count

    def _score_attachments(
        self,
        attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]],
    ) -> Tuple[float, List[str], int]:
        """Evaluate attachment static forensics (20% weight)."""
        reports: List[AttachmentReport] = []
        if isinstance(attachment_report, AttachmentAnalysisReport):
            reports = attachment_report.attachments
        elif isinstance(attachment_report, list):
            reports = attachment_report

        if not reports:
            return 0.0, ["Attachments: No email attachments present."], 0

        points = 0.0
        factors: List[str] = []
        threat_count = 0

        for att in reports:
            # 1. Critical malicious indicators (disguised binaries, EICAR, nested executables)
            if att.verdict == "malicious" or att.mismatch:
                points = max(points, 1.0)
                threat_count += 2
                indicators_hint = f" ({att.suspicious_indicators[0]})" if att.suspicious_indicators else ""
                factors.append(
                    f"Attachments: Critical malicious payload detected in '{att.filename}'{indicators_hint}."
                )

            # 2. Macro enabled documents
            elif att.macro_present is True:
                points = max(points, 0.70)
                threat_count += 1
                factors.append(
                    f"Attachments: Embedded VBA automation macros detected in Office document '{att.filename}'."
                )

            # 3. Suspicious archives or structure
            elif att.verdict == "suspicious" or (att.suspicious_indicators and len(att.suspicious_indicators) > 0):
                points = max(points, 0.45)
                threat_count += 1
                factors.append(
                    f"Attachments: Suspicious indicators flagged in '{att.filename}': {att.suspicious_indicators[0]}."
                )

        if points == 0.0:
            factors.append(
                f"Attachments: All {len(reports)} attachment(s) passed static forensic analysis cleanly."
            )

        return points, factors, threat_count

    def _score_ioc_geo(
        self,
        ioc_set: Optional[IOCSet],
        geo_report: Optional[GeoEnrichmentReport],
    ) -> Tuple[float, List[str], int]:
        """Evaluate IOCs and Geolocation signals for suspicious patterns (20% weight)."""
        points = 0.0
        factors: List[str] = []
        threat_count = 0

        if not ioc_set and not geo_report:
            return 0.0, ["IOC/Geo: No network IOCs or geolocation telemetry available."], 0

        # 1. Inspect URLs for IP-in-URL obfuscation
        if ioc_set and ioc_set.urls:
            raw_ip_urls = [u for u in ioc_set.urls if IP_IN_URL_PATTERN.search(u)]
            if raw_ip_urls:
                points += 0.50
                threat_count += 1
                factors.append(
                    f"IOC Signals: Message body contains raw IP URL destination(s) ({raw_ip_urls[0]})."
                )

        # 2. Inspect domains and URLs for suspicious/abuse TLDs
        matched_tlds: Set[str] = set()
        if ioc_set:
            all_domains = ioc_set.domains + [
                re.sub(r"^https?://([^/:]+).*", r"\1", u) for u in ioc_set.urls
            ]
            for dom in all_domains:
                d_lower = dom.lower()
                for tld in SUSPICIOUS_TLDS:
                    if d_lower.endswith(tld):
                        matched_tlds.add(tld)

        if matched_tlds:
            points += 0.50
            threat_count += 1
            factors.append(
                f"IOC Signals: Identified communication with high-abuse top-level domain(s): {', '.join(sorted(matched_tlds))}."
            )

        # 3. Multiple external target domains
        if ioc_set and len(ioc_set.domains) > 4:
            points += 0.20
            factors.append(
                f"IOC Signals: Unusually high number of disparate domains extracted ({len(ioc_set.domains)} domains)."
            )

        # 4. Geolocation failures or anomalous routing
        if geo_report and geo_report.results:
            failed_geos = [r for r in geo_report.results if r.status == "fail"]
            if failed_geos:
                points += 0.20
                factors.append(
                    f"Geolocation: {len(failed_geos)} public IP hop(s) returned unresolvable/anomalous routing metadata."
                )

        if points == 0.0:
            factors.append(
                "IOC/Geo: No anomalous network infrastructure or suspicious domain patterns detected."
            )

        raw_score = min(1.0, points)
        return raw_score, factors, threat_count

    def _map_verdict(self, risk_score: float) -> str:
        """Map numeric risk score (0.0 to 1.0) to categorical threat verdict."""
        if risk_score < 0.30:
            return ThreatVerdict.LOW.value
        elif risk_score < 0.60:
            return ThreatVerdict.MEDIUM.value
        elif risk_score <= 0.85:
            return ThreatVerdict.HIGH.value
        else:
            return ThreatVerdict.CRITICAL.value


# Global singleton engine instance
_fusion_engine_instance: Optional[EvidenceFusionEngine] = None


def get_fusion_engine() -> EvidenceFusionEngine:
    """Get or initialize singleton EvidenceFusionEngine."""
    global _fusion_engine_instance
    if _fusion_engine_instance is None:
        _fusion_engine_instance = EvidenceFusionEngine()
    return _fusion_engine_instance


def fuse_evidence(
    auth_result: Optional[AuthResult] = None,
    ioc_set: Optional[IOCSet] = None,
    ml_result: Optional[MLClassificationResult] = None,
    geo_report: Optional[GeoEnrichmentReport] = None,
    attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]] = None,
) -> FusionResult:
    """Convenience function to compute evidence fusion from sub-module outputs."""
    return get_fusion_engine().fuse(
        auth_result=auth_result,
        ioc_set=ioc_set,
        ml_result=ml_result,
        geo_report=geo_report,
        attachment_report=attachment_report,
    )


def analyze_and_fuse_email(
    parsed_email: ParsedEmail,
    include_details: bool = True,
) -> FusionResult:
    """Convenience function to run the full forensic pipeline and fuse results."""
    return get_fusion_engine().analyze_and_fuse_email(
        parsed_email=parsed_email,
        include_details=include_details,
    )
