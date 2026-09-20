"""
MAVERICK — Attachment Static Forensics Engine (Module 6)
Analyzes attachments strictly in-memory without runtime execution.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import logging
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import magic
import oletools.olevba
import pefile

from maverick.forensics.models import (
    ArchiveInfo,
    AttachmentAnalysisReport,
    AttachmentReport,
    Hashes,
    PEHeaderInfo,
)
from maverick.parser.models import Attachment, ParsedEmail

logger = logging.getLogger(__name__)

# Standard EICAR Antivirus Test Signature
EICAR_SIG = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Dangerous extensions commonly used in email threat delivery
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".ps1", ".ps1xml", ".hta", ".iso", ".img",
    ".com", ".pif", ".cpl", ".msi", ".msp", ".jar", ".wsf", ".wsh"
}

# Suspicious double extension regex (e.g. invoice.pdf.exe)
DOUBLE_EXT_PATTERN = re.compile(
    r"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|com|pif|jar|msi)$"
)

# Office extensions subject to macro inspection
OFFICE_EXTENSIONS = {
    ".doc", ".docx", ".docm", ".dot", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
    ".ppt", ".pptx", ".pptm", ".pot", ".potm",
}


class AttachmentAnalyzer:
    """
    Static forensic analyzer for email attachments.
    Never executes or writes files to disk with execution permissions.
    """

    def analyze(
        self,
        filename: str,
        data: bytes,
        claimed_type: Optional[str] = None,
    ) -> AttachmentReport:
        """
        Perform complete static forensic examination on an attachment's raw bytes:
        - Cryptographic hashing (MD5, SHA-1, SHA-256)
        - Magic byte file type detection & mismatch flagging
        - Office VBA macro extraction (oletools)
        - PE header inspection (pefile)
        - ZIP archive manifest inspection (zipfile)
        - EICAR malware test signature recognition
        """
        filename = filename or "unnamed_attachment"
        claimed_type = claimed_type or "application/octet-stream"
        file_size = len(data)

        # 1. Cryptographic Hashes
        hashes = self._compute_hashes(data)

        # 2. Magic byte detection
        detected_mime, detected_type = self._detect_magic(data)

        # 3. Detect Claimed Type vs Detected Type Mismatches
        mismatch, mismatch_indicators = self._check_mismatch(
            filename, claimed_type, detected_mime, detected_type
        )

        suspicious_indicators: List[str] = list(mismatch_indicators)

        # 4. Check for known EICAR test signature
        if EICAR_SIG in data or hashes.get("sha256") == EICAR_SHA256:
            suspicious_indicators.append("Known Anti-Malware Test Pattern (EICAR Standard Signature)")

        # 5. Office Macro Inspection
        macro_present, macro_indicators = self._inspect_office_macros(filename, data, detected_mime)
        suspicious_indicators.extend(macro_indicators)

        # 6. Windows Portable Executable (PE) Inspection
        pe_info, pe_indicators = self._inspect_pe_headers(filename, data, detected_mime)
        suspicious_indicators.extend(pe_indicators)

        # 7. ZIP Archive Inspection
        archive_info, archive_indicators = self._inspect_archive(filename, data, detected_mime)
        suspicious_indicators.extend(archive_indicators)

        # 8. Check direct filename for double extensions
        if DOUBLE_EXT_PATTERN.search(filename):
            suspicious_indicators.append(
                f"Suspicious double extension detected in attachment filename: '{filename}'"
            )

        # 9. Determine Forensic Verdict
        verdict = self._determine_verdict(suspicious_indicators, mismatch, macro_present)

        return AttachmentReport(
            filename=filename,
            file_size=file_size,
            hashes=hashes,
            claimed_type=claimed_type,
            detected_type=detected_type,
            detected_mime=detected_mime,
            mismatch=mismatch,
            macro_present=macro_present,
            suspicious_indicators=suspicious_indicators,
            pe_info=pe_info,
            archive_info=archive_info,
            verdict=verdict,
        )

    def analyze_parsed_email(self, parsed_email: ParsedEmail) -> AttachmentAnalysisReport:
        """Analyze all attachments in a ParsedEmail object."""
        import base64

        reports: List[AttachmentReport] = []
        for att in parsed_email.attachments:
            payload = att.raw_bytes if att.raw_bytes else b""
            if not payload and att.content_base64:
                try:
                    payload = base64.b64decode(att.content_base64)
                except Exception:
                    payload = b""

            # If payload bytes were omitted during JSON serialization across network boundaries,
            # avoid false-positive MIME mismatch flags on empty byte array.
            if not payload and att.size_bytes > 0:
                report = AttachmentReport(
                    filename=att.filename,
                    file_size=att.size_bytes,
                    hashes={"md5": att.md5, "sha256": att.sha256},
                    claimed_type=att.content_type,
                    detected_type="Omitted payload (metadata only)",
                    detected_mime=att.content_type,
                    mismatch=False,
                    macro_present=None,
                    pe_info=None,
                    archive_info=None,
                    suspicious_indicators=[],
                    verdict="clean",
                )
                reports.append(report)
                continue

            report = self.analyze(
                filename=att.filename,
                data=payload,
                claimed_type=att.content_type,
            )
            reports.append(report)

        suspicious_count = sum(1 for r in reports if r.verdict in ("suspicious", "malicious"))

        return AttachmentAnalysisReport(
            total_attachments=len(reports),
            suspicious_count=suspicious_count,
            attachments=reports,
        )

    def _compute_hashes(self, data: bytes) -> Dict[str, str]:
        """Compute MD5, SHA-1, and SHA-256 hex digests."""
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _detect_magic(self, data: bytes) -> Tuple[str, str]:
        """Detect actual file MIME and descriptive type using magic bytes."""
        if not data:
            return "application/x-empty", "empty file"

        try:
            detected_mime = magic.from_buffer(data, mime=True)
            detected_type = magic.from_buffer(data)
        except Exception as exc:
            logger.warning("python-magic failed to inspect buffer: %s", exc)
            detected_mime = "application/octet-stream"
            detected_type = "unknown data"

        # Complement with well-known magic byte signatures
        if data.startswith(b"MZ"):
            detected_mime = "application/x-dosexec"
            detected_type = "PE32/PE32+ executable (Windows)"
        elif data.startswith(b"%PDF-"):
            detected_mime = "application/pdf"
            detected_type = "PDF document"
        elif data.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            detected_mime = "application/x-ole-storage"
            detected_type = "Composite Document File V2 (OLE CFBF)"
        elif data.startswith(b"PK\x03\x04"):
            if "zip" not in detected_mime.lower() and "office" not in detected_mime.lower():
                detected_mime = "application/zip"
                detected_type = "Zip archive data"

        return detected_mime, detected_type

    def _check_mismatch(
        self,
        filename: str,
        claimed_type: str,
        detected_mime: str,
        detected_type: str,
    ) -> Tuple[bool, List[str]]:
        """Compare detected file type against claimed MIME type and extension."""
        mismatch = False
        indicators: List[str] = []
        ext = os.path.splitext(filename.lower())[1]

        claimed_lower = claimed_type.lower()
        detected_lower = detected_mime.lower()

        # Check 1: Executable disguised as document or media
        if detected_lower in ("application/x-dosexec", "application/x-msdownload", "application/x-executable"):
            if ext not in (".exe", ".dll", ".sys", ".scr"):
                mismatch = True
                indicators.append(
                    f"CRITICAL: Executable binary disguised with non-executable extension '{ext}' (detected: {detected_type})"
                )
            if "dosexec" not in claimed_lower and "executable" not in claimed_lower and "octet-stream" not in claimed_lower:
                mismatch = True
                indicators.append(
                    f"MIME Mismatch: Claimed '{claimed_type}' but payload is a Windows executable binary"
                )

        # Check 2: Claimed PDF but not PDF bytes
        elif ext == ".pdf" or "application/pdf" in claimed_lower:
            if detected_lower not in ("application/pdf", "application/octet-stream") and not detected_lower.startswith("text/"):
                mismatch = True
                indicators.append(
                    f"MIME Mismatch: Claimed PDF document, but magic bytes indicate '{detected_mime}' ({detected_type})"
                )

        # Check 3: Claimed Office document but completely different structure
        elif ext in OFFICE_EXTENSIONS:
            expected_mimes = (
                "application/msword",
                "application/vnd.ms-excel",
                "application/vnd.ms-powerpoint",
                "application/vnd.openxmlformats-officedocument",
                "application/x-ole-storage",
                "application/zip",
                "application/octet-stream",
            )
            if not any(exp in detected_lower for exp in expected_mimes):
                mismatch = True
                indicators.append(
                    f"MIME Mismatch: Claimed Office document '{ext}', but magic bytes indicate '{detected_mime}'"
                )

        return mismatch, indicators

    def _inspect_office_macros(
        self,
        filename: str,
        data: bytes,
        detected_mime: str,
    ) -> Tuple[Optional[bool], List[str]]:
        """Inspect Office files for embedded VBA macros using oletools."""
        ext = os.path.splitext(filename.lower())[1]
        is_office = ext in OFFICE_EXTENSIONS or "ole" in detected_mime or "msword" in detected_mime or "openxmlformats" in detected_mime

        if not is_office and not data.startswith((b"\xD0\xCF\x11\xE0", b"PK\x03\x04")):
            return None, []

        vba_parser = None
        try:
            vba_parser = oletools.olevba.VBA_Parser(filename, data=data)
            has_macros = vba_parser.detect_vba_macros()

            if not has_macros:
                return False, []

            indicators = [f"Embedded VBA macros detected in Office file: '{filename}'"]

            # Analyze extracted macro code for suspicious calls
            try:
                analysis = vba_parser.analyze_macros()
                suspicious_keywords = set()
                for kw_type, keyword, description in analysis:
                    if kw_type in ("AutoExec", "Suspicious", "IOC"):
                        suspicious_keywords.add(f"{keyword} ({description})")

                if suspicious_keywords:
                    top_k = sorted(list(suspicious_keywords))[:5]
                    indicators.append(
                        f"Suspicious VBA triggers found: {', '.join(top_k)}"
                    )
            except Exception as an_exc:
                logger.debug("VBA keyword analysis failed: %s", an_exc)

            return True, indicators

        except Exception as exc:
            logger.debug("oletools macro inspection skipped/failed: %s", exc)
            return False, []
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass

    def _inspect_pe_headers(
        self,
        filename: str,
        data: bytes,
        detected_mime: str,
    ) -> Tuple[Optional[PEHeaderInfo], List[str]]:
        """Extract static PE header metadata without executing or unpacking."""
        if not data.startswith(b"MZ"):
            return None, []

        pe = None
        indicators: List[str] = []
        try:
            pe = pefile.PE(data=data, fast_load=True)
            machine_code = pe.FILE_HEADER.Machine
            machine_name = pefile.MACHINE_TYPE.get(machine_code, hex(machine_code))

            timestamp = None
            try:
                timestamp = datetime.datetime.fromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc
                ).isoformat()
            except Exception:
                timestamp = str(pe.FILE_HEADER.TimeDateStamp)

            entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            num_sections = pe.FILE_HEADER.NumberOfSections
            subsystem_code = pe.OPTIONAL_HEADER.Subsystem
            subsystem_name = pefile.SUBSYSTEM_TYPE.get(subsystem_code, hex(subsystem_code))

            section_names: List[str] = []
            is_packed = False

            for s in pe.sections:
                name = s.Name.decode("utf-8", errors="replace").strip("\x00")
                section_names.append(name)
                # Check for packing entropy indicators (> 7.2 out of 8.0 indicates high entropy)
                try:
                    entropy = s.get_entropy()
                    if entropy > 7.3:
                        is_packed = True
                except Exception:
                    pass

            if is_packed:
                indicators.append(
                    "High entropy section detected in PE binary (possible obfuscation or packing)"
                )

            pe_info = PEHeaderInfo(
                machine=machine_name,
                compile_timestamp=timestamp,
                entry_point=entry_point,
                number_of_sections=num_sections,
                section_names=section_names,
                subsystem=subsystem_name,
                is_packed=is_packed,
            )

            indicators.append(
                f"Valid Windows PE header parsed statically: architecture={machine_name}, sections={num_sections}"
            )
            return pe_info, indicators

        except Exception as exc:
            logger.debug("pefile inspection failed: %s", exc)
            return None, []
        finally:
            if pe is not None:
                try:
                    pe.close()
                except Exception:
                    pass

    def _inspect_archive(
        self,
        filename: str,
        data: bytes,
        detected_mime: str,
    ) -> Tuple[Optional[ArchiveInfo], List[str]]:
        """Inspect ZIP archive manifest purely in-memory without extracting files."""
        if not data.startswith(b"PK\x03\x04"):
            return None, []

        # Don't treat docx/xlsx as standard user archives
        ext = os.path.splitext(filename.lower())[1]
        if ext in OFFICE_EXTENSIONS:
            return None, []

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                namelist = zf.namelist()
                total_files = len(namelist)

                nested_exes: List[str] = []
                double_exts: List[str] = []
                has_suspicious_paths = False

                for name in namelist:
                    # Path traversal check
                    if ".." in name or name.startswith(("/", "\\")):
                        has_suspicious_paths = True

                    # Nested executable check
                    sub_ext = os.path.splitext(name.lower())[1]
                    if sub_ext in EXECUTABLE_EXTENSIONS:
                        nested_exes.append(name)

                    # Double extension check
                    if DOUBLE_EXT_PATTERN.search(name):
                        double_exts.append(name)

                indicators: List[str] = []
                if nested_exes:
                    indicators.append(
                        f"Archive contains nested executable payload(s): {', '.join(nested_exes[:3])}"
                    )
                if double_exts:
                    indicators.append(
                        f"Archive contains deceptive double-extension file(s): {', '.join(double_exts[:3])}"
                    )
                if has_suspicious_paths:
                    indicators.append(
                        "Archive contains suspicious path traversal filenames (e.g. '../')"
                    )

                archive_info = ArchiveInfo(
                    total_files=total_files,
                    file_names=namelist[:25],
                    nested_executables=nested_exes,
                    double_extensions=double_exts,
                    has_suspicious_paths=has_suspicious_paths,
                )

                return archive_info, indicators

        except Exception as exc:
            logger.debug("zip archive inspection failed: %s", exc)
            return None, []

    def _determine_verdict(
        self,
        indicators: List[str],
        mismatch: bool,
        macro_present: Optional[bool],
    ) -> str:
        """Determine overall forensic verdict based on detected indicators."""
        ind_text = " ".join(indicators).lower()

        # Severe indicators warrant malicious verdict
        if "eicar" in ind_text or "critical: executable binary disguised" in ind_text:
            return "malicious"

        if "nested executable" in ind_text or "double extension" in ind_text or "suspicious vba triggers" in ind_text:
            return "malicious"

        # Suspicious indicators
        if mismatch or macro_present is True or len(indicators) > 0:
            return "suspicious"

        return "clean"


# Shared analyzer instance
_analyzer_instance: Optional[AttachmentAnalyzer] = None


def get_analyzer() -> AttachmentAnalyzer:
    """Get or initialize singleton AttachmentAnalyzer."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = AttachmentAnalyzer()
    return _analyzer_instance


def analyze_attachment(
    filename: str,
    data: bytes,
    claimed_type: Optional[str] = None,
) -> AttachmentReport:
    """Convenience function to statically analyze an attachment's raw bytes."""
    return get_analyzer().analyze(filename=filename, data=data, claimed_type=claimed_type)


def analyze_email_attachments(parsed_email: ParsedEmail) -> AttachmentAnalysisReport:
    """Convenience function to statically analyze all attachments in a ParsedEmail."""
    return get_analyzer().analyze_parsed_email(parsed_email)
