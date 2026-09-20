# MAVERICK: Email Threat Forensic Platform

MAVERICK is an email threat forensic platform. It provides a multi-stage forensic analysis pipeline for detecting spoofing, phishing, and malformed email attacks.

---

## Module 1: EML / MIME Forensic Parser (`/parser`)

The foundation of the MAVERICK forensic pipeline. This module decodes raw `.eml` and MIME messages into a structured object (`ParsedEmail`) that downstream modules consume for threat detection, authentication analysis (SPF/DKIM/DMARC), hop-by-hop IP geolocation tracing, and attachment sandboxing.

### Key Capabilities
- **RFC Header Extraction**: Case-preserved dictionary with multi-value header preservation and RFC 2047 internationalized header decoding.
- **Body Separation**: Distinct extraction of `body_plain` and `body_html`.
- **Forensic Attachment Handling**: Extracts payloads, filenames, sizes, and calculates hex **MD5** and **SHA-256** digests.
- **Received Hop Chain**: Chronologically ordered list of hops with IP extraction (IPv4/IPv6) and inter-hop transit latency calculations (`delay_seconds`).
- **Anomaly Detection**: Flags missing headers, broken boundaries, and date formatting errors in `forensic_warnings`.

---

## Module 2: Email Authentication Forensics (`/auth`)

Evaluates the cryptographic integrity and routing legitimacy of emails by analyzing SPF, DKIM, DMARC, and RFC 7489 Identifier Alignment against the visible `From:` header.

### Key Capabilities
- **Authentication-Results Header Parser**: Full RFC 7601 / RFC 8601 parsing of `Authentication-Results` and `ARC-Authentication-Results` headers with resilient regex fallback.
- **Direct Fallback Verification**: If headers are missing, runs direct cryptographic signature checks via `dkimpy` and SPF route verification via `pyspf` against client IPs in the Received hop chain.
- **Domain Identifier Alignment**: Evaluates both relaxed (organizational root domain matching) and strict (exact FQDN) alignment between `From:`, `Return-Path`, and DKIM `d=`.
- **Spoofing Alerting**: Automatically issues forensic security warnings when high-risk domain mismatches or forged sender identities are detected.

---

## Module 3: Threat Intelligence / IOC Extraction (`/intel/ioc.py`)

Harvests and categorizes Indicators of Compromise (IOCs) across email headers and body content, isolating internal/reserved infrastructure into an exclusion set.

### Key Capabilities
- **IP Address Tagging & Segregation**:
  - Extracts IPs from Received header hops and message body text.
  - Tags each IP with source (`"header"` or `"body"`).
  - Automatically routes RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks, and link-local addresses into `excluded_ips` for forensic reporting while preserving routable IPs in `ips`.
- **Deep URL Harvesting**:
  - Extracts HTML `<a href="...">`, `<img src="...">`, `<form action="...">`, and text URIs.
  - Automatically un-defangs security obfuscations (e.g. `hxxps://` -> `https://`, `[.]` -> `.`).
- **Domain Harvesting**: Extracts unique FQDN hosts and root organizational domains from URLs and body emails.
- **Mentioned Body Emails**: Extracts emails mentioned in the body while strictly filtering out envelope headers (`From`, `To`, `Cc`, `Bcc`, `Return-Path`, `Reply-To`).

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Python API Usage

```python
from maverick.parser import parse_eml
from maverick.auth import analyze_email_auth
from maverick.intel import extract_iocs

# 1. Parse email (Module 1)
parsed = parse_eml("samples/sample_ioc_rich.eml")

# 2. Run authentication forensics (Module 2)
auth = analyze_email_auth(parsed)
print(f"SPF: {auth.spf}, DKIM: {auth.dkim}, DMARC: {auth.dmarc}, Aligned: {auth.aligned}")

# 3. Harvest IOCs (Module 3)
iocs = extract_iocs(parsed)
print("Public IPs:", [i.ip for i in iocs.ips])
print("Excluded IPs (RFC 1918):", [i.ip for i in iocs.excluded_ips])
print("URLs:", iocs.urls)
print("Domains:", iocs.domains)
print("Body Emails:", iocs.emails)
```

---

## FastAPI Service

Launch the combined FastAPI server:

```powershell
uvicorn maverick.api:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI / Swagger documentation is available at:
`http://127.0.0.1:8000/docs`

### API Endpoints

1. **`POST /parse`**: Accepts `.eml` upload and returns `ParsedEmail` JSON.
2. **`POST /auth-check`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `AuthResult` JSON.
3. **`POST /extract-iocs`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `IOCSet` JSON:
   ```json
   {
     "ips": [
       {"ip": "198.51.100.45", "source": "header", "version": 4, "is_private": false, "notes": "Received hop #1"},
       {"ip": "203.0.113.88", "source": "body", "version": 4, "is_private": false, "notes": "Extracted from message body text"}
     ],
     "urls": [
       "https://phish-secure.xyz/portal?token=abc",
       "https://tracking.beacon-analytics.com/pixel.gif",
       "https://c2-control.net/payload.exe"
     ],
     "domains": [
       "phish-secure.xyz",
       "tracking.beacon-analytics.com",
       "beacon-analytics.com",
       "c2-control.net",
       "external-leak.org"
     ],
     "emails": [
       "whistleblower@external-leak.org",
       "threat-intel@external-scam.org"
     ],
     "excluded_ips": [
       {"ip": "10.0.0.15", "source": "header", "version": 4, "is_private": true, "notes": "RFC 1918 / Private subnet"},
       {"ip": "127.0.0.1", "source": "body", "version": 4, "is_private": true, "notes": "Loopback address"}
     ]
   }
   ```

---

## Module 4: Machine Learning Inference (`/ml`)

Provides low-latency threat classification on email body text using pre-trained ML models and TF-IDF representations.

### Key Capabilities
- **Zero Per-Request Overhead**: Model (`phishing_model.pkl`) and TF-IDF vectorizer (`vectorizer.pkl`) are loaded into memory once at startup via a thread-safe singleton (`MLClassifier`).
- **Directional Feature Attribution**: Computes term contributions (`impact = weight * tfidf`) to surface top influential lexical terms driving either the phishing or benign classification.
- **Resilient Preprocessing**: Robust `clean_text` pipeline normalizes HTML, URLs, and emails while gracefully handling empty, whitespace, or micro-body edge cases without throwing exceptions.
- **Pipeline Interoperability**: Seamlessly classifies `ParsedEmail` objects (from Module 1) or standalone text inputs.

---

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Python API Usage

```python
from maverick.parser import parse_eml
from maverick.auth import analyze_email_auth
from maverick.intel import extract_iocs
from maverick.ml import classify_parsed_email, classify_text

# 1. Parse email (Module 1)
parsed = parse_eml("samples/sample_phishing.eml")

# 2. Run authentication forensics (Module 2)
auth = analyze_email_auth(parsed)
print(f"SPF: {auth.spf}, DKIM: {auth.dkim}, DMARC: {auth.dmarc}, Aligned: {auth.aligned}")

# 3. Harvest IOCs (Module 3)
iocs = extract_iocs(parsed)
print("Public IPs:", [i.ip for i in iocs.ips])
print("Excluded IPs (RFC 1918):", [i.ip for i in iocs.excluded_ips])
print("URLs:", iocs.urls)
print("Domains:", iocs.domains)
print("Body Emails:", iocs.emails)

# 4. Predict phishing threat & influential terms (Module 4)
ml_result = classify_parsed_email(parsed, top_k=5)
print(f"Prediction: {ml_result.predicted_label} (Probability: {ml_result.phishing_probability})")
for term in ml_result.top_influential_terms:
    print(f"  - {term.term} (weight: {term.weight}, impact: {term.impact}, indicator: {term.indicator})")

# 5. IP Geolocation & ASN Enrichment (Module 5)
from maverick.intel import geolocate_ioc_set
geo_report = geolocate_ioc_set(iocs)
print("Geolocation Enrichment (Inferred):", geo_report.disclaimer)
for geo in geo_report.results:
    print(f"  - {geo.ip}: {geo.city}, {geo.country} | ASN: {geo.asn} | ISP: {geo.isp}")
```

---

## Module 5: IP Geolocation & ASN Enrichment (`/intel/geo.py`)

Enriches non-excluded, public routable IP addresses harvested by Module 3 with physical location and network ownership data using `ip-api.com`.

### Key Capabilities
- **Batch Processing**: Groups up to 100 IPs per batch request, respecting the 45 req/min free-tier rate limit.
- **Session-Level In-Memory Caching**: Eliminates duplicate network queries for recurring hops and infrastructure across an investigation session.
- **Evidentiary Caveat**: Explicitly flags output as `"inferred_enrichment"` with a formal disclaimer denoting that IP geolocation databases represent probabilistic third-party telemetry rather than directly observed RFC header facts.
- **Fault-Tolerant Resilience**: Network timeouts, HTTP 429 throttling, or unresolvable IPs return per-IP error flags (`status="fail"`) rather than failing the entire batch report.

---

## Module 6: Attachment Static Forensics (`/forensics`)

Performs strictly non-executing, in-memory static forensics on email attachments, protecting investigators from code execution risks.

### Key Capabilities
- **Strict Non-Execution Guarantee**: All inspection (magic byte discovery, macro analysis, PE header inspection, archive walking) is conducted entirely in-memory without invoking runtime code or writing executable files to disk.
- **Cryptographic Hashing**: Simultaneously computes MD5, SHA-1, and SHA-256 digests.
- **Magic Byte & Mismatch Detection**: Discovers true file formats via `python-magic` and flags discrepancies where executables or scripts are disguised as harmless documents (`invoice.pdf` possessing Windows PE `MZ` bytes).
- **VBA Macro Extraction (`oletools`)**: Statically parses Office containers (`.doc`, `.docx`, `.docm`, `.xls`, `.xlsx`, `.xlsm`) to detect embedded macros and surface suspicious triggers (`AutoOpen`, `Shell`, `Action_Click`, `CreateObject`).
- **PE Header Parsing (`pefile`)**: Safely parses Windows Portable Executable headers, extracting architecture, section entropy (flagging packing/cryptor obfuscation), and entry point without unpacking.
- **ZIP Container Inspection**: Walks archives without extracting files to disk, detecting nested executables, path traversal attempts (`../`), and deceptive double extensions (`report.pdf.exe`).
- **Signature Recognition**: Instantly identifies known anti-malware patterns such as the EICAR standard test signature.

---

## Module 7: Evidence Fusion Scoring (`/fusion`)

Synthesizes multi-dimensional forensic telemetry across all upstream modules (Auth, IOCs, ML, Geo, Attachments) into a unified, weighted risk score (0.0 to 1.0) and categorical threat verdict.

### Weighted Risk Formula
- **40% — Machine Learning Phishing Probability** ($0.40 \times P_{\text{phish}}$)
- **20% — Email Authentication Failures** ($0.20 \times S_{\text{auth}}$: SPF/DKIM/DMARC failures, identity misalignment)
- **20% — Attachment Static Forensics** ($0.20 \times S_{\text{att}}$: payload mismatch, macros, disguised executables)
- **20% — Threat Intelligence & Geolocation** ($0.20 \times S_{\text{ioc}}$: raw IP URLs, high-abuse TLDs, anomalous routing)

### Threat Verdict Mapping
| Risk Score Range | Verdict | Description |
|---|---|---|
| `< 0.30` | **Low** | Legitimate message passing security checks cleanly |
| `0.30 - 0.60` | **Medium** | Minor anomalies or moderate phishing likelihood |
| `0.60 - 0.85` | **High** | Multiple suspicious signals, spoofing, or strong phishing indicators |
| `> 0.85` | **Critical** | Severe threat: malicious attachments, active credential harvesting, forged identity |

---

## FastAPI Service

Launch the combined FastAPI server:

```powershell
uvicorn maverick.api:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI / Swagger documentation is available at:
`http://127.0.0.1:8000/docs`

### API Endpoints

1. **`POST /parse`**: Accepts `.eml` upload and returns `ParsedEmail` JSON.
2. **`POST /auth-check`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `AuthResult` JSON.
3. **`POST /extract-iocs`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `IOCSet` JSON.
4. **`POST /classify`**: Accepts `ParsedEmail` JSON, `{"text": "..."}`, raw text string, or `.eml` multipart upload and returns `MLClassificationResult` JSON.
5. **`POST /geolocate`**: Accepts `IOCSet` JSON, `ParsedEmail` JSON, `{"ips": ["..."]}`, or `.eml` upload and returns `GeoEnrichmentReport` JSON.
6. **`POST /analyze-attachment`**: Accepts attachment binary upload, `.eml` upload, or `ParsedEmail` JSON and returns `AttachmentReport` / `AttachmentAnalysisReport` JSON.
7. **`POST /fuse`**: Orchestrates all forensic modules end-to-end for an uploaded `.eml` or chained `ParsedEmail` JSON:
   ```json
   {
     "risk_score": 0.9858,
     "verdict": "Critical",
     "contributing_factors": [
       "Machine Learning: High confidence phishing text detected (97.1% probability) (prominent terms: click, url_token, money, claim).",
       "Authentication: DMARC verification failed (status: FAIL).",
       "Attachments: Critical malicious payload detected in 'document.pdf' (CRITICAL: Executable binary disguised with non-executable extension '.pdf').",
       "IOC Signals: Message body contains raw IP URL destination(s) (http://198.51.100.99/verify)."
     ],
     "score_breakdown": {
       "ml_phishing": 0.3858,
       "authentication": 0.2000,
       "attachments": 0.2000,
       "ioc_geo": 0.2000
     },
     "threat_indicators_count": 4,
     "summary": "Overall threat assessed as CRITICAL (Risk Score: 0.99/1.00) with 4 suspicious/malicious indicators identified across forensics modules."
   }
   ```

---

## Module 8: Automated Forensic Incident Report (`/reports`)

Synthesizes the complete findings of all 7 forensic modules into an executive-ready, multi-page **PDF report** (built in-memory using ReportLab) and a parallel **JSON export**, secured by a cryptographic **SHA-256 integrity hash**.

### Key Capabilities
- **Unique Case ID Generation**: Automatic generation of timestamped, content-deterministic case IDs: `MAV-YYYYMMDD-HHMMSS-{HEX8}`.
- **Executive PDF Incident Report**:
  - Branded header banner with colored threat verdict badge (Critical, High, Medium, Low).
  - 10 distinct investigation sections: Case Summary, Threat Assessment, Evidence Fusion Breakdown, Machine Learning Phishing Findings, Email Authentication Forensics, IOC Evidence & Excluded RFC 1918 Subnets, Geolocation Intelligence (with Inferred Telemetry Caveat), Attachment Static Forensics (hashes, magic bytes, macros, PE info), Hop-by-Hop Timeline, and Prioritized Recommendations.
  - Page numbering with running confidentiality headers and footers (`Page X of Y`).
- **Parallel JSON Export**: Complete structured object with identical evidence telemetry.
- **Evidentiary Integrity Stamping**: The compiled PDF is hashed with SHA-256 in memory and recorded in the JSON output (`pdf_sha256`), providing non-repudiation for court and SOC audit compliance.
- **Dynamic Incident Recommendations**: Rules-based engine mapping threat signals to concrete remediation steps (DMARC policy updates, credential revocation, EDR binary sweeps, firewall IP/domain blacklisting).

---

## FastAPI Service

Launch the combined FastAPI server:

```powershell
uvicorn maverick.api:app --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI / Swagger documentation is available at:
`http://127.0.0.1:8000/docs`

### API Endpoints

1. **`POST /parse`**: Accepts `.eml` upload and returns `ParsedEmail` JSON.
2. **`POST /auth-check`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `AuthResult` JSON.
3. **`POST /extract-iocs`**: Accepts `ParsedEmail` JSON or `.eml` upload and returns `IOCSet` JSON.
4. **`POST /classify`**: Accepts `ParsedEmail` JSON, `{"text": "..."}`, raw text string, or `.eml` multipart upload and returns `MLClassificationResult` JSON.
5. **`POST /geolocate`**: Accepts `IOCSet` JSON, `ParsedEmail` JSON, `{"ips": ["..."]}`, or `.eml` upload and returns `GeoEnrichmentReport` JSON.
6. **`POST /analyze-attachment`**: Accepts attachment binary upload, `.eml` upload, or `ParsedEmail` JSON and returns `AttachmentReport` / `AttachmentAnalysisReport` JSON.
7. **`POST /fuse`**: Orchestrates all forensic modules end-to-end for an uploaded `.eml` or chained `ParsedEmail` JSON and returns `FusionResult` JSON.
8. **`POST /generate-report`**: Runs the complete pipeline end-to-end (Modules 1 through 8) given an uploaded `.eml` or chained `ParsedEmail` JSON:
   - `format=json` (default): Returns JSON with `case_id`, `pdf_sha256`, `pdf_filename`, base64-encoded PDF binary (`pdf_base64`), and complete structured `report`.
   - `format=pdf`: Streams the compiled PDF file directly with `Content-Disposition: attachment` and `X-PDF-SHA256` headers.
9. **`GET /reports/{case_id}/pdf`**: Downloads the cached PDF report by Case ID.
10. **`GET /reports/{case_id}/json`**: Retrieves the cached structured JSON report by Case ID.
11. **`POST /api/submissions`**: Submits an `.eml` email for background forensic analysis and persistence into the SQLite database. Generates and stores the signed PDF report in `data/reports/`, returning a minimal confirmation object with the assigned `case_id`.
12. **`GET /api/submissions`**: Analyst triage queue endpoint. Returns all submissions sorted by threat priority (`Critical` &rarr; `High` &rarr; `Medium` &rarr; `Low`) with aggregate operational counters and optional filters (`status`, `verdict`, `search`).
13. **`GET /api/submissions/{case_id}`**: Retrieves complete submission metadata and full structured forensic report JSON.
14. **`PATCH /api/submissions/{case_id}/status`**: Updates submission review status (`New` &harr; `Reviewed`).
15. **`GET /api/submissions/{case_id}/pdf`**: Streams the persisted forensic PDF report directly from disk.

---

## Web Interfaces & Operational Workflows

MAVERICK provides three dedicated web interfaces tailored for enterprise threat response workflows:

### 1. User Submission Portal (`GET /` or `GET /submit`)

A public-facing portal allowing employees and users to report suspicious emails safely:
- **Clean Drag-and-Drop Uploader**: Accepts any RFC 822 `.eml` file with instant file validation.
- **Asynchronous Ingestion**: Triggers the full 8-module forensic pipeline in the background and commits findings to SQLite.
- **Minimal Confirmation**: Returns a clean confirmation card with the generated **Case ID** and copy button.
- **Strict Reporter Isolation**: Threat verdicts, risk scores, and evidence details are strictly isolated from the reporter to prevent employee panic and thwart threat-actor reconnaissance.

### 2. Security Analyst Review Dashboard (`GET /admin`)

An operations-grade SOC triage dashboard designed for forensic review and incident response:
- **Priority-Driven Queue**: Submissions are automatically ordered by threat severity (`Critical` &rarr; `High` &rarr; `Medium` &rarr; `Low`), with secondary sorting by submission timestamp (newest first).
- **Executive Counter Badges**: Live counters for Total Submissions, Pending New, Critical Threats, and High Severity cases.
- **Real-Time Filtering**: Filter by review status (`New`, `Reviewed`), verdict level, or search by filename or Case ID.
- **One-Click Status Toggle**: Mark cases as `Reviewed` or restore to `New` with instant UI updates.
- **Expandable Forensic Dossier**: Expand any row to inspect deep-dive forensic tabs:
  - **Fusion Breakdown**: 4-pillar risk contribution bars and automated reasoning factors.
  - **ML Phishing**: Neural network classification probability, confidence, and top influential lexical tokens.
  - **Authentication**: Cryptographic verification of SPF, DKIM, and RFC 7489 DMARC alignment status.
  - **IOCs & Geolocation**: Extracted public IPs, URLs, domains, excluded subnets, and IP-API geolocation telemetry table.
  - **Attachments**: Static forensic analysis (magic byte verification, MIME mismatch alerts, VBA macro markers, PE headers, hashes).
  - **Hop Timeline & Recommendations**: Inter-MTA transit delays and prioritized incident response actions.
- **One-Click PDF Download**: Direct download button to stream the signed forensic PDF report from `data/reports/`.

### 3. Live Demonstration Interface (`GET /demo`)

A high-contrast, projector-optimized live demonstration tool designed for conference rooms, executive briefings, and live presentations:
- **One-Click Demo Presets**: Instant load buttons for:
  - 🚨 **Phishing Attack** (`sample_phishing.eml`)
  - 🛡️ **Clean Corporate** (`sample_clean.eml`)
  - ⚠️ **Spoofed Auth** (`sample_auth_spoofed.eml`)
  - ☣️ **Disguised Malware** (`attachment_04_disguised_executable_pdf.eml`)
- **Direct Interactive Inspector**: View verdicts, risk scores, and full forensic evidence in real time.

---

## Running the Full Test Suite

MAVERICK includes a comprehensive test suite covering all modules, models, pipelines, persistence layers, and API endpoints:

```powershell
python -m pytest -v
```

*(**97 automated tests passing** across parser, auth, intel, ml, geo, forensics, fusion, reports, db persistence, submissions API, and UI endpoints)*




