"""FastAPI Service for MAVERICK Forensic EML Parser."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple
from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

from maverick.parser.engine import parse_eml
from maverick.parser.models import ParsedEmail

UI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui")
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")

app = FastAPI(
    title="MAVERICK Forensic Email Platform - Module 1: Parser",
    description=(
        "Forensic .eml / MIME parser service. Extracts headers, bodies (plain & HTML), "
        "attachments with MD5/SHA256 hashes, and reconstructs the Received MTA hop chain."
    ),
    version="0.1.0",
)

# Enable CORS for frontend forensic dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "maverick-parser", "version": "0.1.0"}


@app.post(
    "/parse",
    tags=["Forensic Parsing"],
    summary="Parse an uploaded .eml file or raw MIME bytes",
    response_description="Structured forensic email object with headers, body, attachments, and hops",
)
async def parse_email_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Uploaded .eml file (multipart/form-data)"
    ),
    include_attachment_bytes: bool = Query(
        default=False,
        description="Whether to include base64-encoded attachment byte content in JSON response",
    ),
) -> Dict[str, Any]:
    """
    Parse a raw .eml file and return a fully structured forensic representation:
    - **headers**: Case-preserved dict with multi-value support
    - **body_plain** & **body_html**: Clean extracted body representations
    - **attachments**: Filenames, MIME types, sizes, and MD5/SHA256 digests
    - **received_chain**: Ordered hops (earliest origin to destination) with timestamps and transit delays
    - **forensic_warnings**: Header anomalies, missing RFC fields, or boundary issues
    """
    raw_content: bytes = b""

    if file is not None:
        try:
            raw_content = await file.read()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read uploaded file: {str(exc)}",
            )
    else:
        # Check if raw bytes were submitted directly in the request body
        try:
            body = await request.body()
            if body and body.strip():
                raw_content = body
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read request body: {str(exc)}",
            )

    if not raw_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No .eml file or raw email content provided. Upload via multipart 'file' or raw body.",
        )

    try:
        parsed: ParsedEmail = parse_eml(raw_content)
        return parsed.to_api_dict(include_attachment_bytes=include_attachment_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic parsing error: {str(exc)}",
        )


@app.post(
    "/auth-check",
    tags=["Email Authentication"],
    summary="Evaluate SPF, DKIM, DMARC, and domain alignment forensics",
    response_description="Forensic AuthResult with statuses, alignment checks, and security notes",
)
async def auth_check_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Optional .eml file upload"
    ),
    strict_alignment: bool = Query(
        default=False,
        description="Enforce strict FQDN alignment instead of relaxed organizational domain matching",
    ),
) -> Dict[str, Any]:
    """
    Perform authentication forensics on an email:
    - Analyzes **Authentication-Results** header (SPF, DKIM, DMARC).
    - Falls back to direct **dkimpy** and **pyspf** checks if headers are absent.
    - Evaluates **RFC 7489 Identifier Alignment** between From: domain, Return-Path, and DKIM d=.
    - Returns structured **AuthResult** JSON with forensic audit notes.
    """
    from maverick.auth import analyze_email_auth

    parsed_email: Optional[ParsedEmail] = None
    raw_bytes: Optional[bytes] = None

    if file is not None:
        try:
            raw_bytes = await file.read()
            parsed_email = parse_eml(raw_bytes)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process uploaded file: {str(exc)}",
            )
    else:
        # Check request body
        try:
            body = await request.body()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read request body: {str(exc)}",
            )

        if not body or not body.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty payload provided. Submit ParsedEmail JSON or raw .eml file.",
            )

        # Check if content is JSON representing a ParsedEmail
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                parsed_email = ParsedEmail.model_validate_json(body)
            except Exception as json_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ParsedEmail JSON object: {json_exc}",
                )
        else:
            # Assume raw .eml bytes
            raw_bytes = body
            try:
                parsed_email = parse_eml(raw_bytes)
            except Exception as parse_exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to parse raw EML stream: {parse_exc}",
                )

    if not parsed_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to resolve ParsedEmail for authentication analysis.",
        )

    try:
        auth_result = analyze_email_auth(
            parsed_email=parsed_email,
            raw_eml_bytes=raw_bytes,
            strict_alignment=strict_alignment,
        )
        return auth_result.model_dump()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication analysis error: {str(exc)}",
        )


@app.post(
    "/extract-iocs",
    tags=["Threat Intelligence"],
    summary="Extract and deduplicate IPs, URLs, domains, and mentioned emails",
    response_description="Structured IOCSet with public IOCs and segregated private infrastructure",
)
async def extract_iocs_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Optional .eml file upload"
    ),
) -> Dict[str, Any]:
    """
    Harvest threat intelligence IOCs from an email:
    - **ips**: Public routable IPs tagged as 'header' or 'body'.
    - **urls**: De-fanged and normalized URLs from plain text and HTML attributes (href, src).
    - **domains**: Extracted host domains from URLs, hostnames, and body emails.
    - **emails**: Email addresses mentioned in body text (strictly excluding From/To/Cc envelope headers).
    - **excluded_ips**: RFC 1918, loopback, and link-local private IPs preserved for forensics.
    """
    from maverick.intel import extract_iocs

    parsed_email: Optional[ParsedEmail] = None

    if file is not None:
        try:
            raw_bytes = await file.read()
            parsed_email = parse_eml(raw_bytes)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process uploaded file: {str(exc)}",
            )
    else:
        try:
            body = await request.body()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read request body: {str(exc)}",
            )

        if not body or not body.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty payload provided. Submit ParsedEmail JSON or raw .eml file.",
            )

        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                parsed_email = ParsedEmail.model_validate_json(body)
            except Exception as json_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ParsedEmail JSON object: {json_exc}",
                )
        else:
            try:
                parsed_email = parse_eml(body)
            except Exception as parse_exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to parse raw EML stream: {parse_exc}",
                )

    if not parsed_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to resolve ParsedEmail for IOC harvesting.",
        )

    try:
        ioc_set = extract_iocs(parsed_email)
        return ioc_set.to_api_dict()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"IOC extraction error: {str(exc)}",
        )


@app.post(
    "/classify",
    tags=["Machine Learning"],
    summary="Predict phishing probability and extract top influential lexical terms",
    response_description="Classification decision with phishing_probability and influential terms",
)
async def classify_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Optional .eml file upload"
    ),
    top_k: int = Query(
        default=8,
        description="Number of top influential terms to extract for the predicted class",
    ),
) -> Dict[str, Any]:
    """
    Perform machine learning phishing inference on email body text:
    - Pre-trained TF-IDF vectorizer + classifier loaded in memory once at startup.
    - Returns **phishing_probability**, **predicted_label** ('phishing' or 'benign'),
      and **top_influential_terms** with individual feature weights and contributions.
    """
    from maverick.ml import classify_parsed_email, classify_text

    if file is not None:
        try:
            raw_bytes = await file.read()
            parsed_email = parse_eml(raw_bytes)
            result = classify_parsed_email(parsed_email, top_k=top_k)
            return result.to_api_dict()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process uploaded file: {str(exc)}",
            )

    # Read body
    try:
        body = await request.body()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read request body: {str(exc)}",
        )

    if not body or not body.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload provided. Submit ParsedEmail JSON, text body, or .eml file.",
        )

    content_type = request.headers.get("content-type", "")

    # 1. Check if JSON payload
    if "application/json" in content_type:
        import json
        try:
            json_data = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as j_exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid JSON payload: {j_exc}",
            )

        if isinstance(json_data, dict):
            # Check if this is a ParsedEmail object
            if "body_plain" in json_data or "headers" in json_data:
                try:
                    parsed_email = ParsedEmail.model_validate(json_data)
                    result = classify_parsed_email(parsed_email, top_k=top_k)
                    return result.to_api_dict()
                except Exception as p_exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Invalid ParsedEmail object: {p_exc}",
                    )
            # Check if { "text": "..." }
            elif "text" in json_data:
                result = classify_text(str(json_data["text"]), top_k=top_k)
                return result.to_api_dict()

    # 2. Raw text string
    raw_str = body.decode("utf-8", errors="replace").strip()
    if raw_str.startswith("From:") or raw_str.startswith("Received:") or raw_str.startswith("Return-Path:"):
        try:
            parsed_email = parse_eml(body)
            result = classify_parsed_email(parsed_email, top_k=top_k)
            return result.to_api_dict()
        except Exception:
            pass

    # Fallback to direct raw text classification
    result = classify_text(raw_str, top_k=top_k)
    return result.to_api_dict()


@app.post(
    "/geolocate",
    tags=["Threat Intelligence"],
    summary="Geolocate public IP addresses and enrich with ASN and ISP metadata",
    response_description="Enriched geolocation report with country, city, ASN, ISP, and inferred enrichment disclaimers",
)
async def geolocate_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Optional .eml file upload"
    ),
    timeout: float = Query(
        default=5.0,
        description="Network timeout in seconds for ip-api.com batch lookups",
    ),
) -> Dict[str, Any]:
    """
    Enrich public routable IPs with geolocation and ASN metadata via ip-api.com:
    - **In-Memory Caching**: Session cache prevents redundant queries for identical IPs.
    - **Batch Processing**: Batches queries up to 100 IPs to respect API rate limits.
    - **Resilient Errors**: Partial lookups flag individual IPs rather than failing the whole batch.
    - **Evidentiary Disclaimer**: Output is explicitly flagged as 'inferred_enrichment'.
    """
    from maverick.intel import (
        IOCSet,
        geolocate_ioc_set,
        geolocate_ips,
        geolocate_parsed_email,
    )

    if file is not None:
        try:
            raw_bytes = await file.read()
            parsed_email = parse_eml(raw_bytes)
            report = geolocate_parsed_email(parsed_email, timeout=timeout)
            return report.to_api_dict()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process uploaded file for geolocation: {str(exc)}",
            )

    try:
        body = await request.body()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read request body: {str(exc)}",
        )

    if not body or not body.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload. Provide an IOCSet JSON, ParsedEmail JSON, IP list JSON, or .eml file.",
        )

    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        import json
        try:
            json_data = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as j_exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid JSON payload: {j_exc}",
            )

        # 1. Check if IOCSet JSON
        if isinstance(json_data, dict) and "excluded_ips" in json_data and "ips" in json_data:
            try:
                ioc_set = IOCSet.model_validate(json_data)
                report = geolocate_ioc_set(ioc_set, timeout=timeout)
                return report.to_api_dict()
            except Exception as ioc_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid IOCSet structure: {ioc_exc}",
                )

        # 2. Check if ParsedEmail JSON
        if isinstance(json_data, dict) and ("body_plain" in json_data or "headers" in json_data):
            try:
                parsed_email = ParsedEmail.model_validate(json_data)
                report = geolocate_parsed_email(parsed_email, timeout=timeout)
                return report.to_api_dict()
            except Exception as p_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ParsedEmail structure: {p_exc}",
                )

        # 3. Check if { "ips": [...] }
        if isinstance(json_data, dict) and "ips" in json_data:
            ips_list = json_data["ips"]
            if isinstance(ips_list, list):
                # Could be list of strings or list of objects
                raw_ips = [
                    item["ip"] if isinstance(item, dict) and "ip" in item else str(item)
                    for item in ips_list
                ]
                report = geolocate_ips(raw_ips, timeout=timeout)
                return report.to_api_dict()

        # 4. Check if direct list of IPs: ["8.8.8.8", "1.1.1.1"]
        if isinstance(json_data, list):
            raw_ips = [
                item["ip"] if isinstance(item, dict) and "ip" in item else str(item)
                for item in json_data
            ]
            report = geolocate_ips(raw_ips, timeout=timeout)
            return report.to_api_dict()

    # Fallback to plain text or email parsing
    raw_str = body.decode("utf-8", errors="replace").strip()
    if raw_str.startswith("From:") or raw_str.startswith("Received:") or raw_str.startswith("Return-Path:"):
        try:
            parsed_email = parse_eml(body)
            report = geolocate_parsed_email(parsed_email, timeout=timeout)
            return report.to_api_dict()
        except Exception:
            pass

    import re
    # Extract candidate IP tokens from raw text
    tokens = [t.strip() for t in re.split(r"[\s,;]+", raw_str) if t.strip()]
    report = geolocate_ips(tokens, timeout=timeout)
    return report.to_api_dict()


@app.post(
    "/analyze-attachment",
    tags=["Forensics"],
    summary="Perform static forensic analysis on an attachment or email attachments",
    response_description="Forensic report with hashes, magic byte type detection, macro checks, and PE headers",
)
async def analyze_attachment_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Attachment file or .eml message to statically inspect",
    ),
) -> Dict[str, Any]:
    """
    Perform purely static, in-memory forensic analysis on email attachments:
    - **Cryptographic Hashing**: SHA-256, SHA-1, MD5 hex digests.
    - **Magic Byte Identification**: Discovers true file type and flags MIME/extension mismatches.
    - **Office VBA Macro Inspection**: Checks .doc/.docx/.xls for macros and extracts suspicious triggers.
    - **PE Header Parsing**: Extracts architecture, section names, and entropy without execution.
    - **Archive Inspection**: Recursively lists ZIP contents, flagging nested executables & double extensions.
    - **Signature Matching**: Recognizes known test threats (e.g. EICAR standard pattern).
    """
    from maverick.forensics import (
        analyze_attachment,
        analyze_email_attachments,
    )

    if file is not None:
        try:
            raw_bytes = await file.read()
            filename = file.filename or "attachment.bin"

            # Check if an .eml email was uploaded
            if filename.lower().endswith(".eml") or raw_bytes.startswith((b"From:", b"Received:", b"Return-Path:")):
                try:
                    parsed_email = parse_eml(raw_bytes)
                    analysis = analyze_email_attachments(parsed_email)
                    return analysis.to_api_dict()
                except Exception:
                    pass

            # Otherwise, analyze as an individual uploaded attachment
            report = analyze_attachment(
                filename=filename,
                data=raw_bytes,
                claimed_type=file.content_type or "application/octet-stream",
            )
            return report.to_api_dict()

        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process uploaded file: {str(exc)}",
            )

    try:
        body = await request.body()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read request body: {str(exc)}",
        )

    if not body or not body.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload provided. Submit an attachment file, .eml file, or ParsedEmail JSON.",
        )

    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        import base64
        import json
        try:
            json_data = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as j_exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid JSON payload: {j_exc}",
            )

        # 1. ParsedEmail structure with attachments
        if isinstance(json_data, dict) and "attachments" in json_data:
            try:
                parsed_email = ParsedEmail.model_validate(json_data)
                analysis = analyze_email_attachments(parsed_email)
                return analysis.to_api_dict()
            except Exception as p_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ParsedEmail object: {p_exc}",
                )

        # 2. Individual attachment JSON object
        if isinstance(json_data, dict):
            att_name = json_data.get("filename", "unnamed.bin")
            claimed_mime = json_data.get("mime_type") or json_data.get("claimed_type") or "application/octet-stream"
            att_data = b""
            if "content_base64" in json_data:
                try:
                    att_data = base64.b64decode(json_data["content_base64"])
                except Exception as b_exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Invalid base64 payload: {b_exc}",
                    )
            elif "data" in json_data:
                att_data = str(json_data["data"]).encode("utf-8")
            elif "raw_bytes" in json_data:
                att_data = str(json_data["raw_bytes"]).encode("utf-8")

            report = analyze_attachment(filename=att_name, data=att_data, claimed_type=claimed_mime)
            return report.to_api_dict()

    # Fallback to direct bytes or EML
    raw_str = body.decode("utf-8", errors="replace").strip()
    if raw_str.startswith("From:") or raw_str.startswith("Received:") or raw_str.startswith("Return-Path:"):
        try:
            parsed_email = parse_eml(body)
            analysis = analyze_email_attachments(parsed_email)
            return analysis.to_api_dict()
        except Exception:
            pass

    # Direct raw bytes analysis
    report = analyze_attachment(filename="attachment.bin", data=body, claimed_type="application/octet-stream")
    return report.to_api_dict()


@app.post(
    "/fuse",
    tags=["Fusion"],
    summary="Synthesize multi-dimensional forensic evidence into an actionable risk score and verdict",
    response_description="Composite risk score, verdict, score breakdown, and plain-language contributing factors",
)
async def fuse_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Uploaded .eml message to analyze across all forensic dimensions",
    ),
    include_details: bool = Query(
        default=True,
        description="Whether to include detailed sub-module reports in response",
    ),
) -> Dict[str, Any]:
    """
    Evidence Fusion Orchestrator (Module 7):
    - Invokes and aggregates:
      - **40%**: ML Phishing probability & influential lexical terms
      - **20%**: Email Authentication (SPF, DKIM, DMARC, Domain Alignment)
      - **20%**: Attachment Static Forensics (hashes, magic bytes, macros, PE headers)
      - **20%**: IOC & Geolocation Reputation Signals (suspicious TLDs, IP-in-URL, routing)
    - Maps composite score to **Low**, **Medium**, **High**, or **Critical** threat verdict.
    - Generates executive-ready, plain-language **contributing_factors**.
    """
    from maverick.fusion import analyze_and_fuse_email, fuse_evidence

    if file is not None:
        try:
            raw_bytes = await file.read()
            parsed_email = parse_eml(raw_bytes)
            fusion_result = analyze_and_fuse_email(parsed_email, include_details=include_details)
            return fusion_result.to_api_dict()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to process email for fusion analysis: {str(exc)}",
            )

    try:
        body = await request.body()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read request body: {str(exc)}",
        )

    if not body or not body.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload provided. Submit a .eml file or ParsedEmail JSON.",
        )

    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        import json
        try:
            json_data = json.loads(body.decode("utf-8", errors="replace"))
        except Exception as j_exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid JSON payload: {j_exc}",
            )

        # 1. Check if ParsedEmail JSON object
        if isinstance(json_data, dict) and ("body_plain" in json_data or "headers" in json_data):
            try:
                parsed_email = ParsedEmail.model_validate(json_data)
            except Exception as p_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ParsedEmail object: {p_exc}",
                )
            try:
                fusion_result = analyze_and_fuse_email(parsed_email, include_details=include_details)
                return fusion_result.to_api_dict()
            except Exception as f_exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Evidence fusion engine error: {f_exc}",
                )

        # 2. Check if pre-computed modules JSON payload
        if isinstance(json_data, dict) and any(k in json_data for k in ("auth", "iocs", "ml", "geo", "attachments")):
            from maverick.auth.models import AuthResult
            from maverick.forensics.models import AttachmentAnalysisReport
            from maverick.intel.models import GeoEnrichmentReport, IOCSet
            from maverick.ml.models import MLClassificationResult

            auth_res = AuthResult.model_validate(json_data["auth"]) if "auth" in json_data else None
            ioc_res = IOCSet.model_validate(json_data["iocs"]) if "iocs" in json_data else None
            ml_res = MLClassificationResult.model_validate(json_data["ml"]) if "ml" in json_data else None
            geo_res = GeoEnrichmentReport.model_validate(json_data["geo"]) if "geo" in json_data else None
            att_res = AttachmentAnalysisReport.model_validate(json_data["attachments"]) if "attachments" in json_data else None

            fusion_result = fuse_evidence(
                auth_result=auth_res,
                ioc_set=ioc_res,
                ml_result=ml_res,
                geo_report=geo_res,
                attachment_report=att_res,
            )
            return fusion_result.to_api_dict()

    # Fallback to direct raw EML stream
    raw_str = body.decode("utf-8", errors="replace").strip()
    if raw_str.startswith("From:") or raw_str.startswith("Received:") or raw_str.startswith("Return-Path:"):
        try:
            parsed_email = parse_eml(body)
            fusion_result = analyze_and_fuse_email(parsed_email, include_details=include_details)
            return fusion_result.to_api_dict()
        except Exception as p_exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse EML stream: {p_exc}",
            )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Payload not recognized. Provide a .eml message or ParsedEmail JSON.",
    )


# In-memory forensic reports cache for session retrieval
_REPORT_CACHE: Dict[str, Tuple[Any, bytes]] = {}


@app.post(
    "/generate-report",
    tags=["Forensic Reports"],
    summary="Generate comprehensive forensic incident report in PDF and JSON with SHA-256 integrity digest",
    response_description="Forensic investigation report in PDF binary download or structured JSON with base64 PDF",
)
async def generate_report_endpoint(
    request: Request,
    file: Optional[UploadFile] = File(
        default=None,
        description="Uploaded .eml message to analyze across all forensic dimensions",
    ),
    format: str = Query(
        default="json",
        description="Output format: 'json' (structured JSON report with base64 PDF) or 'pdf' (direct PDF file download)",
    ),
    include_pdf_base64: bool = Query(
        default=True,
        description="Whether to include base64-encoded PDF binary in JSON response",
    ),
) -> Any:
    """
    Automated Forensic Incident Report Generator (Module 8):
    - Executes the entire MAVERICK pipeline end-to-end:
      1. RFC 822 / MIME Parsing & Hop Extraction
      2. SPF / DKIM / DMARC Authentication & Alignment Verification
      3. Indicator of Compromise (IOC) Harvesting & RFC 1918 Segregation
      4. Machine Learning Phishing Probability & Lexical Term Attribution
      5. Public IP-API Geolocation Telemetry
      6. In-Memory Static Attachment Forensics (Hashes, Magic Bytes, Macros, PE Headers)
      7. Multi-Dimensional Evidence Fusion Scoring & Threat Verdict
      8. Incident Response Recommendations & Hop Timeline
    - Generates an executive-ready, multi-page PDF using ReportLab.
    - Computes a cryptographic SHA-256 integrity hash of the compiled PDF for chain of custody.
    - Returns either direct PDF download (`format=pdf`) or structured JSON with embedded PDF bytes (`format=json`).
    """
    import base64
    import json
    from maverick.auth import analyze_email_auth
    from maverick.forensics import analyze_email_attachments
    from maverick.fusion import fuse_evidence
    from maverick.intel import extract_iocs, geolocate_ioc_set
    from maverick.ml import classify_parsed_email
    from maverick.reports import (
        build_forensic_report,
        generate_full_report,
        run_full_pipeline_and_generate_report,
    )

    raw_bytes: Optional[bytes] = None
    parsed_email: Optional[ParsedEmail] = None

    if file is not None:
        try:
            raw_bytes = await file.read()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read uploaded file: {exc}",
            )
    else:
        try:
            body = await request.body()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to read request body: {exc}",
            )

        if not body or not body.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty payload provided. Submit a .eml file, raw email text, or ParsedEmail JSON.",
            )

        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                json_data = json.loads(body.decode("utf-8", errors="replace"))
            except Exception as j_exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid JSON payload: {j_exc}",
                )

            if isinstance(json_data, dict) and ("body_plain" in json_data or "headers" in json_data):
                try:
                    parsed_email = ParsedEmail.model_validate(json_data)
                except Exception as p_exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Invalid ParsedEmail object: {p_exc}",
                    )
            else:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="JSON payload must represent a valid ParsedEmail object.",
                )
        else:
            raw_bytes = body

    try:
        if raw_bytes is not None:
            report, pdf_bytes = run_full_pipeline_and_generate_report(raw_bytes)
        elif parsed_email is not None:
            auth_res = analyze_email_auth(parsed_email)
            ioc_res = extract_iocs(parsed_email)
            ml_res = classify_parsed_email(parsed_email)
            geo_res = geolocate_ioc_set(ioc_res)
            att_res = analyze_email_attachments(parsed_email)
            fusion_res = fuse_evidence(
                auth_result=auth_res,
                ioc_set=ioc_res,
                ml_result=ml_res,
                geo_report=geo_res,
                attachment_report=att_res,
            )
            report, pdf_bytes = generate_full_report(
                parsed_email=parsed_email,
                auth_result=auth_res,
                ioc_set=ioc_res,
                ml_result=ml_res,
                geo_report=geo_res,
                attachment_report=att_res,
                fusion_result=fusion_res,
                raw_eml_bytes=None,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to determine email source payload.",
            )

        # Cache report in memory
        _REPORT_CACHE[report.case_metadata.case_id] = (report, pdf_bytes)

        # Check export format
        accept_header = request.headers.get("accept", "").lower()
        if format.lower() == "pdf" or "application/pdf" in accept_header:
            filename = f"MAVERICK-Report-{report.case_metadata.case_id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "X-Case-ID": report.case_metadata.case_id,
                    "X-PDF-SHA256": report.pdf_sha256 or "",
                },
            )

        resp_payload: Dict[str, Any] = {
            "case_id": report.case_metadata.case_id,
            "pdf_sha256": report.pdf_sha256,
            "pdf_filename": f"MAVERICK-Report-{report.case_metadata.case_id}.pdf",
            "report": report.to_api_dict(),
        }
        if include_pdf_base64:
            resp_payload["pdf_base64"] = base64.b64encode(pdf_bytes).decode("ascii")

        return resp_payload

    except HTTPException:
        raise
    except Exception as gen_exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Forensic report generation error: {gen_exc}",
        )


@app.get(
    "/reports/{case_id}/pdf",
    tags=["Forensic Reports"],
    summary="Download compiled PDF forensic report by Case ID",
)
async def get_report_pdf(case_id: str) -> Response:
    """Retrieve and stream cached forensic PDF report by Case ID."""
    if case_id not in _REPORT_CACHE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic report for Case ID '{case_id}' not found in active session cache.",
        )
    report, pdf_bytes = _REPORT_CACHE[case_id]
    filename = f"MAVERICK-Report-{case_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Case-ID": case_id,
            "X-PDF-SHA256": report.pdf_sha256 or "",
        },
    )


@app.get(
    "/reports/{case_id}/json",
    tags=["Forensic Reports"],
    summary="Download structured JSON forensic report by Case ID",
)
async def get_report_json(case_id: str) -> Dict[str, Any]:
    """Retrieve structured forensic JSON report by Case ID."""
    if case_id not in _REPORT_CACHE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic report for Case ID '{case_id}' not found in active session cache.",
        )
    report, _ = _REPORT_CACHE[case_id]
    return report.to_api_dict()


# ==============================================================================
# Live Demonstration Web Interface Routes
# ==============================================================================

@app.get(
    "/",
    response_class=HTMLResponse,
    tags=["Demo Interface"],
    summary="Interactive live forensic demonstration interface",
)
async def serve_demo_interface() -> HTMLResponse:
    """Serve the MAVERICK Projector-Optimized Live Forensic Demo Web Interface."""
    index_path = os.path.join(UI_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demo UI index.html not found on server filesystem.",
        )
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read UI template: {exc}",
        )


@app.get(
    "/ui/{filename}",
    tags=["Demo Interface"],
    summary="Serve demo interface static assets (CSS, JS)",
)
async def serve_ui_asset(filename: str) -> Response:
    """Serve styling and client scripts for the demo interface."""
    allowed_assets: Dict[str, Tuple[str, str]] = {
        "style.css": ("text/css; charset=utf-8", "style.css"),
        "app.js": ("application/javascript; charset=utf-8", "app.js"),
    }
    if filename not in allowed_assets:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{filename}' not permitted or not found.",
        )
    media_type, disk_fname = allowed_assets[filename]
    file_path = os.path.join(UI_DIR, disk_fname)
    if not os.path.isfile(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{filename}' missing on server.",
        )
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content=content, media_type=media_type)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read asset {filename}: {exc}",
        )


@app.get(
    "/demo/sample/{sample_name}",
    tags=["Demo Interface"],
    summary="Fetch bundled sample .eml message for instant live demonstration",
)
async def get_demo_sample(sample_name: str) -> Response:
    """Provide quick one-click demo access to standard sample email files."""
    allowed_samples: Dict[str, str] = {
        "sample_phishing.eml": os.path.join(SAMPLES_DIR, "sample_phishing.eml"),
        "sample_clean.eml": os.path.join(SAMPLES_DIR, "sample_clean.eml"),
        "sample_auth_spoofed.eml": os.path.join(SAMPLES_DIR, "sample_auth_spoofed.eml"),
        "sample_malware.eml": os.path.join(
            SAMPLES_DIR, "stress_test", "attachment_04_disguised_executable_pdf.eml"
        ),
    }
    if sample_name not in allowed_samples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Demo sample '{sample_name}' not available. Available: {list(allowed_samples.keys())}",
        )
    target_path = allowed_samples[sample_name]
    if not os.path.isfile(target_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample file '{sample_name}' not found on server disk.",
        )
    try:
        with open(target_path, "rb") as f:
            sample_bytes = f.read()
        return Response(
            content=sample_bytes,
            media_type="message/rfc822",
            headers={"Content-Disposition": f'inline; filename="{sample_name}"'},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read sample file: {exc}",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("maverick.api:app", host="127.0.0.1", port=8000, reload=True)



