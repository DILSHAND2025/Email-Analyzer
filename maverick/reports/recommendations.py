"""Rules-based forensic recommendation engine for MAVERICK incident reports."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from maverick.auth.models import AuthResult
from maverick.forensics.models import AttachmentAnalysisReport, AttachmentReport
from maverick.fusion.models import FusionResult, ThreatVerdict
from maverick.intel.models import GeoEnrichmentReport, IOCSet
from maverick.ml.models import MLClassificationResult
from maverick.reports.models import Recommendation, RecommendationCategory, RecommendationPriority


def generate_recommendations(
    fusion_result: FusionResult,
    auth_result: Optional[AuthResult] = None,
    ioc_set: Optional[IOCSet] = None,
    ml_result: Optional[MLClassificationResult] = None,
    geo_report: Optional[GeoEnrichmentReport] = None,
    attachment_report: Optional[AttachmentAnalysisReport | List[AttachmentReport]] = None,
) -> List[Recommendation]:
    """
    Generate prioritized, actionable incident response recommendations based on forensic findings.
    """
    recs: List[Recommendation] = []
    verdict = fusion_result.verdict

    # 1. Critical Overall Containment
    if verdict in (ThreatVerdict.CRITICAL.value, "Critical"):
        recs.append(
            Recommendation(
                priority=RecommendationPriority.CRITICAL.value,
                category=RecommendationCategory.INCIDENT_RESPONSE.value,
                action="Initiate active threat containment: quarantine email across all tenant mailboxes and isolate affected hosts.",
                rationale=f"Overall composite risk score is {fusion_result.risk_score:.2f} (Critical) with multiple severe attack vectors confirmed.",
            )
        )
    elif verdict in (ThreatVerdict.HIGH.value, "High"):
        recs.append(
            Recommendation(
                priority=RecommendationPriority.HIGH.value,
                category=RecommendationCategory.INCIDENT_RESPONSE.value,
                action="Quarantine suspicious message and monitor recipient account activity for anomalous authentications.",
                rationale=f"Composite risk score is {fusion_result.risk_score:.2f} (High) indicating malicious intent or severe policy violations.",
            )
        )

    # 2. Email Authentication & Identity Remediation
    if auth_result:
        if auth_result.dmarc in ("fail", "permerror") or not auth_result.aligned:
            recs.append(
                Recommendation(
                    priority=RecommendationPriority.HIGH.value,
                    category=RecommendationCategory.IDENTITY_AUTH.value,
                    action=f"Block sender identity and review DMARC enforcement for domain '{auth_result.from_domain or 'unknown'}'.",
                    rationale="DMARC verification failed or sender identity misalignment indicates active email spoofing / impersonation.",
                )
            )
        elif auth_result.spf in ("fail", "softfail"):
            recs.append(
                Recommendation(
                    priority=RecommendationPriority.MEDIUM.value,
                    category=RecommendationCategory.IDENTITY_AUTH.value,
                    action="Verify sending MTA IP against authorized SPF records and inspect relay path for unauthorized intermediate hops.",
                    rationale=f"Sender domain policy returned SPF {auth_result.spf.upper()} status.",
                )
            )

    # 3. Machine Learning Phishing & Credential Defense
    if ml_result and ml_result.phishing_probability >= 0.60:
        priority = RecommendationPriority.CRITICAL.value if ml_result.phishing_probability >= 0.85 else RecommendationPriority.HIGH.value
        recs.append(
            Recommendation(
                priority=priority,
                category=RecommendationCategory.CREDENTIAL_USER.value,
                action="Enforce mandatory password reset and revoke active SSO/OAuth session tokens for recipients.",
                rationale=f"ML phishing classifier detected high-confidence phishing language ({ml_result.phishing_probability*100:.1f}% probability) targeting user credentials.",
            )
        )

    # 4. Attachment Static Forensics & EDR Actions
    att_reports: List[AttachmentReport] = []
    if isinstance(attachment_report, AttachmentAnalysisReport):
        att_reports = attachment_report.attachments
    elif isinstance(attachment_report, list):
        att_reports = attachment_report

    for att in att_reports:
        if att.verdict == "malicious" or att.mismatch:
            recs.append(
                Recommendation(
                    priority=RecommendationPriority.CRITICAL.value,
                    category=RecommendationCategory.MALWARE_ATTACHMENT.value,
                    action=f"Sweep enterprise endpoints with EDR for SHA-256 '{att.hashes.get('sha256', 'unknown')}' and block hash at security gateways.",
                    rationale=f"Attachment '{att.filename}' was confirmed as a disguised or malicious payload ({att.detected_type}).",
                )
            )
        elif att.macro_present is True:
            recs.append(
                Recommendation(
                    priority=RecommendationPriority.HIGH.value,
                    category=RecommendationCategory.MALWARE_ATTACHMENT.value,
                    action=f"Enforce GPO blocking of untrusted Office VBA macros and examine workstation logs for child process execution from '{att.filename}'.",
                    rationale="Office document contains embedded automation macros frequently leveraged in dropper / downloader payloads.",
                )
            )

    # 5. Network, Firewall & IOC Blacklisting
    if ioc_set:
        if ioc_set.urls:
            raw_ip_urls = [u for u in ioc_set.urls if any(char.isdigit() for char in u.split("/")[2:3])]
            if raw_ip_urls:
                recs.append(
                    Recommendation(
                        priority=RecommendationPriority.HIGH.value,
                        category=RecommendationCategory.NETWORK_FIREWALL.value,
                        action=f"Blacklist raw destination IP address(es) across egress firewall and secure web gateway: {raw_ip_urls[0]}.",
                        rationale="Adversary is hosting infrastructure directly on IP addresses to evade domain reputation and DNS filtering.",
                    )
                )

        if ioc_set.domains:
            abuse_domains = [d for d in ioc_set.domains if any(d.lower().endswith(tld) for tld in (".xyz", ".top", ".buzz", ".live", ".tk"))]
            if abuse_domains:
                recs.append(
                    Recommendation(
                        priority=RecommendationPriority.MEDIUM.value,
                        category=RecommendationCategory.NETWORK_FIREWALL.value,
                        action=f"Add high-abuse domain(s) ({', '.join(abuse_domains[:3])}) to DNS sinkhole / protective resolver blocklist.",
                        rationale="Domain infrastructure is registered under known high-abuse / disposable TLDs.",
                    )
                )

    # 6. Baseline Clean Hygiene Recommendation
    if not recs:
        recs.append(
            Recommendation(
                priority=RecommendationPriority.LOW.value,
                category=RecommendationCategory.INCIDENT_RESPONSE.value,
                action="No immediate remediation required. Retain email in normal archive and continue standard security monitoring.",
                rationale="Email passed all forensic, cryptographic, machine learning, and static binary inspections cleanly.",
            )
        )

    return recs
