"""Safe parsing of .eml files and pasted raw headers.

Security notes
--------------
* Input is untrusted. Nothing is executed, rendered or opened.
* Attachments are only *listed* (name, declared type, approximate size); their
  payloads are never decoded or written to disk.
* The message body is not interpreted by this tool.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import List, Optional, Tuple

MAX_BYTES = 10 * 1024 * 1024  # refuse anything larger than 10 MB

# Attachment extensions that are commonly abused to deliver malware / phishing pages.
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com", ".pif",
    ".ps1", ".msi", ".jar", ".lnk", ".iso", ".img", ".hta", ".wsf", ".docm",
    ".xlsm", ".pptm", ".html", ".htm", ".svg", ".chm",
}

_KNOWN_HEADER_NAMES = {
    "from", "to", "received", "subject", "date", "message-id", "return-path",
    "reply-to", "authentication-results", "mime-version", "content-type",
}


class EmailParseError(ValueError):
    """Raised when the input cannot reasonably be treated as an email / header block."""


@dataclass
class ParsedEmail:
    """Structured view of the headers we care about."""

    source_name: str = "pasted headers"
    size_bytes: int = 0
    raw_headers: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)  # (name, value) in file order

    from_raw: str = ""
    from_name: str = ""
    from_addr: str = ""
    from_domain: str = ""
    from_count: int = 0
    to: str = ""
    reply_to_raw: str = ""
    reply_to_addrs: List[str] = field(default_factory=list)
    return_path_raw: str = ""
    return_path_addr: str = ""
    subject: str = ""
    date_raw: str = ""
    date_dt: Optional[datetime] = None
    message_id: str = ""
    message_id_domain: str = ""

    received: List[str] = field(default_factory=list)  # newest first, exactly as in the file
    authentication_results: List[str] = field(default_factory=list)
    received_spf: List[str] = field(default_factory=list)
    dkim_signatures: List[str] = field(default_factory=list)
    x_originating_ip: List[str] = field(default_factory=list)

    attachments: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # ---- presentation helpers -------------------------------------------------
    def metadata_rows(self) -> List[Tuple[str, str]]:
        """Key header fields as (label, value) pairs for tables and reports."""
        return [
            ("From", self.from_raw or "(missing)"),
            ("To", self.to or "(missing)"),
            ("Reply-To", self.reply_to_raw or "(not present)"),
            ("Return-Path", self.return_path_raw or "(not present)"),
            ("Subject", self.subject or "(missing)"),
            ("Date", self.date_raw or "(missing)"),
            ("Message-ID", self.message_id or "(missing)"),
            ("X-Originating-IP", ", ".join(self.x_originating_ip) or "(not present)"),
            ("Received headers", str(len(self.received))),
            ("Authentication-Results headers", str(len(self.authentication_results))),
        ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _clean(value) -> str:
    """Decode RFC 2047 encoded words (best effort) and collapse whitespace."""
    if value is None:
        return ""
    text = str(value)
    try:
        text = str(make_header(decode_header(text)))
    except Exception:  # malformed encoded words: keep the raw text
        pass
    return re.sub(r"\s+", " ", text).strip()


def _collapse(value) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _domain_of(address: str) -> str:
    if address and "@" in address:
        return address.rsplit("@", 1)[1].strip().strip(">").lower()
    return ""


def _addresses(value: str) -> List[Tuple[str, str]]:
    try:
        return [(n, a.strip().lower()) for n, a in getaddresses([value]) if a]
    except Exception:
        return []


def _prepare(data: bytes) -> bytes:
    """Normalise newlines, drop leading blank lines and an mbox 'From ' separator."""
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").lstrip(b"\n")
    if re.match(rb"From \S+", data):  # mbox separator line, not a header
        data = data.split(b"\n", 1)[1] if b"\n" in data else b""
    return data


def _header_block(data: bytes) -> bytes:
    """Everything before the first blank line."""
    m = re.search(rb"\n\n", data)
    return data[: m.start()] if m else data


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def parse_eml_bytes(data: bytes, source_name: str = "uploaded.eml") -> ParsedEmail:
    """Parse the bytes of an .eml file."""
    if not isinstance(data, (bytes, bytearray)):
        raise EmailParseError("Expected raw bytes for an .eml file.")
    if len(data) == 0:
        raise EmailParseError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise EmailParseError(f"The file is larger than the {MAX_BYTES // (1024 * 1024)} MB limit.")
    if b"\x00" in data[:4096]:
        raise EmailParseError("This looks like a binary file, not a text email (.eml).")

    data = _prepare(bytes(data))
    block = _header_block(data)
    raw_headers = block.decode("utf-8", errors="replace")
    names = {n.lower() for n in re.findall(r"(?m)^([A-Za-z][A-Za-z0-9-]*):", raw_headers)}
    if not names & _KNOWN_HEADER_NAMES:
        raise EmailParseError(
            "No recognisable email headers were found. Expected lines such as "
            "'From:', 'Received:' or 'Subject:'."
        )

    try:
        msg = BytesParser(policy=policy.compat32).parsebytes(data)
    except Exception as exc:  # extremely malformed input
        raise EmailParseError(f"The email could not be parsed ({type(exc).__name__}).") from exc

    parsed = ParsedEmail(source_name=source_name, size_bytes=len(data), raw_headers=raw_headers)
    _fill(parsed, msg)
    return parsed


def parse_raw_text(text: str, source_name: str = "pasted headers") -> ParsedEmail:
    """Parse headers (or a whole message) pasted as text."""
    if not text or not text.strip():
        raise EmailParseError("Nothing to analyse: the pasted text is empty.")
    return parse_eml_bytes(text.encode("utf-8", errors="replace"), source_name)


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------
def _fill(p: ParsedEmail, msg) -> None:
    def first(name: str) -> str:
        v = msg.get(name)
        return "" if v is None else str(v)

    def every(name: str) -> List[str]:
        return [str(v) for v in (msg.get_all(name) or [])]

    # Full header list in original order (values cleaned for display).
    p.headers = [(str(k), _clean(v)) for k, v in msg.items()]

    from_values = every("From")
    p.from_count = len(from_values)
    p.from_raw = _clean(from_values[0]) if from_values else ""
    addrs = _addresses(p.from_raw)
    if addrs:
        p.from_name = _clean(addrs[0][0])
        p.from_addr = addrs[0][1]
        p.from_domain = _domain_of(p.from_addr)
    if p.from_count > 1:
        p.warnings.append("The message contains more than one From header.")

    p.to = _clean(first("To"))
    p.reply_to_raw = _clean(first("Reply-To"))
    p.reply_to_addrs = [a for _, a in _addresses(p.reply_to_raw)]

    p.return_path_raw = _clean(first("Return-Path"))
    rp = [a for _, a in _addresses(p.return_path_raw)]
    p.return_path_addr = rp[0] if rp else ""
    if p.return_path_raw and not p.return_path_addr and "<>" not in p.return_path_raw:
        p.warnings.append("Return-Path could not be parsed.")

    p.subject = _clean(first("Subject"))
    p.date_raw = _clean(first("Date"))
    if p.date_raw:
        try:
            dt = parsedate_to_datetime(p.date_raw)
            p.date_dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            p.warnings.append("The Date header could not be parsed.")

    p.message_id = _clean(first("Message-ID"))
    m = re.search(r"@([^>\s]+)", p.message_id)
    p.message_id_domain = m.group(1).lower() if m else ""

    p.received = [_collapse(v) for v in every("Received")]
    p.authentication_results = [_collapse(v) for v in every("Authentication-Results")]
    p.received_spf = [_collapse(v) for v in every("Received-SPF")]
    p.dkim_signatures = [_collapse(v) for v in every("DKIM-Signature")]
    p.x_originating_ip = [_collapse(v) for v in every("X-Originating-IP")]

    # Attachments are described, never decoded.
    try:
        for part in msg.walk():
            if part.is_multipart():
                continue
            filename = _clean(part.get_filename() or "")
            disposition = (part.get_content_disposition() or "").lower()
            if filename or disposition == "attachment":
                name = filename or "(unnamed)"
                lower = name.lower()
                ext = "." + lower.rsplit(".", 1)[1] if "." in lower else ""
                payload = part.get_payload()
                size = len(payload) if isinstance(payload, str) else 0
                p.attachments.append({
                    "filename": name,
                    "content_type": part.get_content_type(),
                    "approx_encoded_size_bytes": size,
                    "risky_extension": ext in RISKY_EXTENSIONS,
                    "double_extension": lower.count(".") >= 2 and ext in RISKY_EXTENSIONS,
                })
    except Exception:
        p.warnings.append("Attachment structure could not be fully inspected.")

    for defect in getattr(msg, "defects", [])[:5]:
        p.warnings.append(f"Parser noted a structural defect: {type(defect).__name__}.")
