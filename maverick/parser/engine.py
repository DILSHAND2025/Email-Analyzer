"""Core MIME / EML Parser Engine for MAVERICK."""

from __future__ import annotations

import email
from email import policy
from email.header import decode_header
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr
import hashlib
import mimetypes
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from maverick.parser.models import Attachment, ParsedEmail, ReceivedHop
from maverick.parser.received import parse_received_chain, parse_timestamp


def decode_mime_words(val: Optional[str]) -> Optional[str]:
    """Safely decode RFC 2047 encoded words in email headers."""
    if not val:
        return None
    try:
        decoded_slices = decode_header(val)
        pieces = []
        for text, encoding in decoded_slices:
            if isinstance(text, bytes):
                enc = encoding or "utf-8"
                try:
                    pieces.append(text.decode(enc, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    pieces.append(text.decode("latin-1", errors="replace"))
            else:
                pieces.append(str(text))
        return "".join(pieces).strip()
    except Exception:
        return str(val).strip()


def safe_decode_payload(payload_bytes: bytes, charset: Optional[str]) -> str:
    """Decode raw payload bytes into string trying declared charset, utf-8, latin1, and replace."""
    if not payload_bytes:
        return ""
    
    candidates = []
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8", "windows-1252", "iso-8859-1", "ascii"])

    for enc in candidates:
        try:
            return payload_bytes.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue

    # Fallback with replacement characters
    return payload_bytes.decode("utf-8", errors="replace")


def sanitize_filename(name: Optional[str], default_ext: str = ".bin", index: int = 1) -> str:
    """Sanitize attachment filename and remove path traversal artifacts."""
    if not name or not name.strip():
        return f"unnamed_attachment_{index}{default_ext}"
    decoded = decode_mime_words(name.strip()) or f"unnamed_attachment_{index}{default_ext}"
    # Strip any directory traversal components
    clean_name = os.path.basename(decoded).replace("/", "_").replace("\\", "_")
    # Replace invalid control characters
    clean_name = re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]', "_", clean_name).strip()
    if not clean_name:
        return f"unnamed_attachment_{index}{default_ext}"
    return clean_name


class EMLParser:
    """High-resilience forensic parser for .eml files and MIME message streams."""

    def __init__(self, fallback_to_compat32: bool = True):
        self.fallback_to_compat32 = fallback_to_compat32

    def parse_file(self, file_path: str) -> ParsedEmail:
        """Parse an EML file on disk."""
        with open(file_path, "rb") as f:
            return self.parse_bytes(f.read(), source_label=file_path)

    def parse_bytes(self, raw_bytes: bytes, source_label: str = "stream") -> ParsedEmail:
        """Parse raw email bytes into structured ParsedEmail object."""
        warnings: List[str] = []

        if not raw_bytes or not raw_bytes.strip():
            warnings.append("Input email stream is empty or contains only whitespace.")
            return ParsedEmail(forensic_warnings=warnings)

        # Primary parse attempt using modern policy.default
        msg = None
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception as exc:
            warnings.append(f"Modern policy.default parser failed: {exc}. Attempting compat32 fallback.")
            if self.fallback_to_compat32:
                try:
                    msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)
                except Exception as fatal_exc:
                    warnings.append(f"Fatal parsing failure: {fatal_exc}")
                    return ParsedEmail(forensic_warnings=warnings)
            else:
                return ParsedEmail(forensic_warnings=warnings)

        # Extract headers
        headers_dict: Dict[str, Union[str, List[str]]] = {}
        raw_headers_list: List[Tuple[str, str]] = []
        received_raw_headers: List[str] = []
        auth_results: List[str] = []

        for k, v in msg.items():
            k_str = str(k).strip()
            v_str = decode_mime_words(str(v)) or str(v)
            raw_headers_list.append((k_str, v_str))

            # Collect for headers dict
            if k_str in headers_dict:
                existing = headers_dict[k_str]
                if isinstance(existing, list):
                    existing.append(v_str)
                else:
                    headers_dict[k_str] = [existing, v_str]
            else:
                headers_dict[k_str] = v_str

            k_lower = k_str.lower()
            if k_lower == "received":
                received_raw_headers.append(str(v))
            elif k_lower in ("authentication-results", "arc-authentication-results"):
                auth_results.append(v_str)

        # Specific core header extraction
        subject = decode_mime_words(msg.get("Subject"))
        from_raw = msg.get("From")
        from_addr = decode_mime_words(from_raw) if from_raw else None

        # Parse addresses for To, CC, BCC
        to_addrs = [addr for _, addr in getaddresses([msg.get("To", "")]) if addr]
        cc_addrs = [addr for _, addr in getaddresses([msg.get("Cc", "")]) if addr]
        bcc_addrs = [addr for _, addr in getaddresses([msg.get("Bcc", "")]) if addr]

        reply_to_raw = msg.get("Reply-To")
        reply_to = decode_mime_words(reply_to_raw) if reply_to_raw else None

        return_path_raw = msg.get("Return-Path")
        return_path = decode_mime_words(return_path_raw) if return_path_raw else None

        date_raw = msg.get("Date")
        date_parsed = parse_timestamp(date_raw) if date_raw else None

        message_id = msg.get("Message-ID")
        if message_id:
            message_id = str(message_id).strip()

        # Check for forensic anomalies in headers
        if not message_id:
            warnings.append("Forensic anomaly: Missing 'Message-ID' header (common in bulk spam/spoofing).")
        if not date_raw:
            warnings.append("Forensic anomaly: Missing 'Date' header.")
        elif not date_parsed:
            warnings.append(f"Forensic anomaly: Malformed or unparseable 'Date' header: '{date_raw}'.")
        if not from_addr:
            warnings.append("Forensic anomaly: Missing 'From' header.")

        # Parse Received chain into hops
        received_hops, hop_warnings = parse_received_chain(received_raw_headers)
        warnings.extend(hop_warnings)
        if not received_hops:
            warnings.append("Forensic anomaly: No 'Received' headers present in email.")

        # Traverse MIME structure for bodies and attachments
        body_plain_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[Attachment] = []
        attachment_counter = 1

        is_multipart = msg.is_multipart()

        def process_part(part: Any):
            nonlocal attachment_counter
            content_type = part.get_content_type().lower()
            content_disposition = part.get_content_disposition()
            raw_filename = part.get_filename()
            content_id = part.get("Content-ID")
            if content_id:
                content_id = str(content_id).strip()

            # Check if this part is an attachment or attached message
            is_attachment = False
            if content_disposition == "attachment":
                is_attachment = True
            elif raw_filename and content_disposition != "inline":
                is_attachment = True
            elif content_type == "message/rfc822":
                is_attachment = True
            elif not part.is_multipart() and content_type not in ("text/plain", "text/html"):
                is_attachment = True

            if is_attachment:
                # Extract attachment payload
                try:
                    payload = part.get_payload(decode=True)
                except Exception as exc:
                    warnings.append(f"Error decoding payload for {content_type}: {exc}")
                    payload = None

                if payload is None:
                    # For message/rfc822 or un-decodable parts
                    sub_msg = part.get_payload()
                    if isinstance(sub_msg, (list, tuple)) and len(sub_msg) > 0:
                        payload = sub_msg[0].as_bytes() if hasattr(sub_msg[0], "as_bytes") else b""
                    elif hasattr(sub_msg, "as_bytes"):
                        payload = sub_msg.as_bytes()
                    elif hasattr(part, "as_bytes"):
                        payload = part.as_bytes()
                    elif isinstance(sub_msg, str):
                        payload = sub_msg.encode("utf-8", errors="replace")
                    else:
                        payload = b""

                guessed_ext = ".eml" if content_type == "message/rfc822" else (mimetypes.guess_extension(content_type) or ".bin")
                final_name = sanitize_filename(raw_filename, default_ext=guessed_ext, index=attachment_counter)
                attachment_counter += 1

                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()

                attachments.append(
                    Attachment(
                        filename=final_name,
                        content_type=content_type,
                        content_disposition=content_disposition or ("inline" if content_id else "attachment"),
                        content_id=content_id,
                        size_bytes=len(payload),
                        md5=md5_hash,
                        sha256=sha256_hash,
                        raw_bytes=payload,
                    )
                )
                # Do not descend into attached sub-messages as parent bodies
                return

            # If it's a multipart container, recursively iterate over its children
            if part.is_multipart():
                subparts = (
                    part.iter_parts()
                    if hasattr(part, "iter_parts")
                    else (part.get_payload() if isinstance(part.get_payload(), list) else [])
                )
                for sub in subparts:
                    process_part(sub)
                return

            # Leaf body or inline part
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception as exc:
                warnings.append(f"Error decoding body payload: {exc}")
                payload = b""

            charset = part.get_content_charset()
            decoded_text = safe_decode_payload(payload, charset)
            if content_type == "text/plain":
                body_plain_parts.append(decoded_text)
            elif content_type == "text/html":
                body_html_parts.append(decoded_text)
            elif content_disposition == "inline" or content_id:
                guessed_ext = mimetypes.guess_extension(content_type) or ".bin"
                final_name = sanitize_filename(raw_filename, default_ext=guessed_ext, index=attachment_counter)
                attachment_counter += 1
                attachments.append(
                    Attachment(
                        filename=final_name,
                        content_type=content_type,
                        content_disposition="inline",
                        content_id=content_id,
                        size_bytes=len(payload),
                        md5=hashlib.md5(payload).hexdigest(),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        raw_bytes=payload,
                    )
                )

        process_part(msg)

        body_plain = "\n\n".join(body_plain_parts).strip()
        body_html = "\n\n".join(body_html_parts).strip()

        return ParsedEmail(
            headers=headers_dict,
            raw_headers=raw_headers_list,
            subject=subject,
            from_addr=from_addr,
            to_addrs=to_addrs,
            cc_addrs=cc_addrs,
            bcc_addrs=bcc_addrs,
            reply_to=reply_to,
            return_path=return_path,
            date=date_raw,
            date_parsed=date_parsed,
            message_id=message_id,
            authentication_results=auth_results,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            received_chain=received_hops,
            is_multipart=is_multipart,
            has_attachments=len(attachments) > 0,
            forensic_warnings=warnings,
        )


def parse_eml(data: Union[str, bytes, os.PathLike]) -> ParsedEmail:
    """Convenience function to parse an EML file path or raw bytes."""
    parser = EMLParser()
    if isinstance(data, (bytes, bytearray)):
        return parser.parse_bytes(bytes(data))
    if isinstance(data, str) and (os.path.exists(data) or len(data) < 1024 and "\n" not in data):
        return parser.parse_file(data)
    if isinstance(data, str):
        return parser.parse_bytes(data.encode("utf-8", errors="replace"))
    if hasattr(data, "__fspath__"):
        return parser.parse_file(str(data))
    raise TypeError(f"Unsupported input type for parse_eml: {type(data)}")
