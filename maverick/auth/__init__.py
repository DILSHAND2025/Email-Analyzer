"""MAVERICK Email Authentication Forensics (Module 2)."""

from maverick.auth.models import (
    AuthResult,
    AuthStatus,
    DKIMDetails,
    DMARCDetails,
    SPFDetails,
)
from maverick.auth.engine import EmailAuthAnalyzer, analyze_email_auth
from maverick.auth.alignment import (
    check_alignment,
    evaluate_domain_alignment,
    extract_domain,
    get_organizational_domain,
)
from maverick.auth.header_parser import AuthenticationResultsParser
from maverick.auth.direct_verifier import DirectAuthVerifier

__all__ = [
    "AuthResult",
    "AuthStatus",
    "DKIMDetails",
    "DMARCDetails",
    "SPFDetails",
    "EmailAuthAnalyzer",
    "analyze_email_auth",
    "check_alignment",
    "evaluate_domain_alignment",
    "extract_domain",
    "get_organizational_domain",
    "AuthenticationResultsParser",
    "DirectAuthVerifier",
]
