"""SPF / DKIM / DMARC analysis based on the results *reported* in message headers.

Important: this tool does not re-run SPF, DKIM or DMARC checks. It reads what the
receiving mail server recorded in ``Authentication-Results`` (and, as a secondary
source for SPF only, ``Received-SPF``). A missing header is reported as UNKNOWN -
never as PASS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

STATUSES = ("PASS", "FAIL", "NONE", "UNKNOWN")

# Raw result keyword -> one of the four display statuses.
_RESULT_MAP = {
    "pass": "PASS",
    "fail": "FAIL", "hardfail": "FAIL", "softfail": "FAIL",
    "none": "NONE", "neutral": "NONE",
    "temperror": "UNKNOWN", "permerror": "UNKNOWN", "policy": "UNKNOWN",
    "bestguesspass": "UNKNOWN", "unknown": "UNKNOWN",
}

NOT_REVERIFIED_NOTE = ("These results are copied from the headers added by the receiving server. "
                       "This tool does not re-verify signatures or DNS records, and headers added before "
                       "the message reached a trusted server could be forged.")


@dataclass
class AuthResult:
    mechanism: str
    status: str = "UNKNOWN"
    raw_result: str = ""        # e.g. "softfail"
    source: str = "not found in headers"
    domain: str = ""            # smtp.mailfrom / header.d / header.from
    detail: str = ""            # parenthesised comment from the header
    entries: List[dict] = field(default_factory=list)


def map_result(raw: str) -> str:
    return _RESULT_MAP.get((raw or "").strip().lower(), "UNKNOWN")


def parse_dkim_signature(value: str) -> dict:
    """Extract d= (domain), s= (selector) and a= (algorithm) from a DKIM-Signature header. No validation."""
    tags = {}
    for key in ("d", "s", "a"):
        m = re.search(rf"(?:^|[;\s]){key}=([^;\s]+)", value or "")
        if m:
            tags[key] = m.group(1)
    return tags


def _parse_one_header(text: str) -> dict:
    """Parse one Authentication-Results header into authserv-id + per-method entries."""
    # Protect ';' inside comments so we can split on real separators.
    safe = re.sub(r"\([^)]*\)", lambda m: m.group(0).replace(";", ","), text or "")
    segments = [s.strip() for s in safe.split(";") if s.strip()]
    authserv = ""
    if segments and not re.match(r"(?i)^(spf|dkim|dmarc|arc|auth|iprev)\s*=", segments[0]):
        authserv = segments[0].split()[0]
        segments = segments[1:]
    entries = []
    for seg in segments:
        m = re.match(r"(?i)^(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)(.*)$", seg)
        if not m:
            continue
        rest = m.group(3)
        comment = re.search(r"\(([^)]*)\)", rest)
        props = dict(re.findall(r"([A-Za-z][\w.-]*)\s*=\s*([^\s;()]+)", re.sub(r"\([^)]*\)", " ", rest)))
        entries.append({
            "mechanism": m.group(1).lower(),
            "raw": m.group(2).lower(),
            "status": map_result(m.group(2)),
            "detail": comment.group(1).strip() if comment else "",
            "props": {k.lower(): v for k, v in props.items()},
        })
    return {"authserv_id": authserv, "entries": entries}


def analyze_authentication(authentication_results: List[str], received_spf: List[str],
                           dkim_signatures: List[str], from_domain: str = "") -> Dict[str, object]:
    """Combine all available evidence into SPF / DKIM / DMARC results.

    Returns a dict with keys ``spf``, ``dkim``, ``dmarc`` (AuthResult), plus
    ``has_auth_results_header``, ``authserv_ids``, ``notes`` and ``dkim_signature_domains``.
    """
    headers = [_parse_one_header(h) for h in (authentication_results or [])]
    notes: List[str] = [NOT_REVERIFIED_NOTE]
    authserv_ids = [h["authserv_id"] for h in headers if h["authserv_id"]]
    if len(set(authserv_ids)) > 1:
        notes.append("Several Authentication-Results headers from different servers are present "
                     f"({', '.join(sorted(set(authserv_ids)))}). Only the topmost (newest) header is used; "
                     "a forged header added by the sender is a known evasion trick.")

    top_entries = headers[0]["entries"] if headers else []
    top_id = headers[0]["authserv_id"] if headers else ""
    source_label = f"Authentication-Results ({top_id or 'server not named'})"

    results: Dict[str, AuthResult] = {}
    for mech in ("spf", "dkim", "dmarc"):
        found = [e for e in top_entries if e["mechanism"] == mech]
        res = AuthResult(mechanism=mech.upper())
        if found:
            statuses = [e["status"] for e in found]
            if mech == "dkim":  # several signatures are possible; any valid one is meaningful
                if "PASS" in statuses:
                    res.status, chosen = "PASS", next(e for e in found if e["status"] == "PASS")
                elif "FAIL" in statuses:
                    res.status, chosen = "FAIL", next(e for e in found if e["status"] == "FAIL")
                else:
                    res.status, chosen = statuses[0], found[0]
                if len(found) > 1:
                    failed = sum(1 for s in statuses if s == "FAIL")
                    notes.append(f"{len(found)} DKIM signatures were evaluated ({failed} failed).")
            else:
                chosen = found[0]
                res.status = chosen["status"]
            res.raw_result = chosen["raw"]
            res.detail = chosen["detail"]
            res.source = source_label
            props = chosen["props"]
            res.domain = (props.get("smtp.mailfrom") or props.get("smtp.helo") or "") if mech == "spf" else \
                         (props.get("header.d") or props.get("header.i") or "") if mech == "dkim" else \
                         props.get("header.from", "")
            if "@" in res.domain:
                res.domain = res.domain.rsplit("@", 1)[1]
            res.entries = found
        results[mech] = res

    # Secondary source for SPF only: Received-SPF.
    spf = results["spf"]
    if spf.status == "UNKNOWN" and received_spf:
        m = re.match(r"(?i)^\s*([A-Za-z]+)\b(.*)$", received_spf[0])
        if m:
            spf.status = map_result(m.group(1))
            spf.raw_result = m.group(1).lower()
            spf.detail = _short(m.group(2))
            spf.source = "Received-SPF header (secondary source)"
            dom = re.search(r"(?i)(?:envelope-from|smtp\.mailfrom|domain of)\s*=?\s*<?([^\s>;]+)", m.group(2))
            if dom:
                spf.domain = dom.group(1).rsplit("@", 1)[-1]

    # DKIM-Signature present but no verdict: say so, do not guess.
    sig_domains = [parse_dkim_signature(s).get("d", "") for s in (dkim_signatures or [])]
    sig_domains = [d for d in sig_domains if d]
    dkim = results["dkim"]
    if dkim.status == "UNKNOWN" and dkim_signatures and not dkim.entries:
        dkim.source = "DKIM-Signature header present, but no verification result recorded"
        dkim.detail = ("A signature exists (d=" + ", ".join(sorted(set(sig_domains))) + ") "
                       if sig_domains else "A signature exists ") + "but nobody recorded whether it verified."
        notes.append("A DKIM-Signature header proves only that the sender attached a signature, not that it is valid.")

    return {
        "spf": results["spf"], "dkim": results["dkim"], "dmarc": results["dmarc"],
        "has_auth_results_header": bool(headers),
        "authserv_ids": authserv_ids,
        "notes": notes,
        "dkim_signature_domains": sorted(set(sig_domains)),
    }


def _short(text: str, limit: int = 160) -> str:
    text = re.sub(r"\s+", " ", text or "").strip(" ()")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def status_counts(auth: Dict[str, object]) -> Dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for key in ("spf", "dkim", "dmarc"):
        counts[auth[key].status] += 1
    return counts
