"""IP extraction/classification, Received-chain analysis and optional IP intelligence.

Key forensic ideas implemented here
-----------------------------------
* Every mail server that handles a message *prepends* a ``Received`` header, so the
  header at the top of the file is the newest. We reverse the list to read the
  route in chronological order (oldest hop first).
* Only headers written by servers you trust are reliable. Anything written
  before the message reached a trusted server can be forged by the sender.
* The first IP found in a header block is NOT automatically the sender. We pick
  the IP recorded by the newest hop that names a non-internal address (what the
  receiving infrastructure actually observed) and report a confidence level that
  is never higher than "Moderate" - headers alone cannot *verify* an origin.
"""
from __future__ import annotations

import ipaddress
import os
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import requests

from .domain_utils import is_ip_literal, normalize_host, registered_domain

# ---------------------------------------------------------------------------
# IP extraction and classification
# ---------------------------------------------------------------------------
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")

_DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")

CATEGORY_NOTES = {
    "public": "Globally routable address.",
    "private": "Private address (RFC 1918 / ULA); only meaningful inside the sender's own network.",
    "loopback": "Loopback address; the message was handed over on the same machine.",
    "link-local": "Link-local address; not routable beyond the local network segment.",
    "multicast": "Multicast address; not a valid mail sender.",
    "unspecified": "Unspecified address (0.0.0.0 / ::).",
    "shared (CGNAT)": "Carrier-grade NAT shared space (100.64.0.0/10); not a public address.",
    "documentation": "Reserved documentation/example range (RFC 5737 / RFC 3849) - synthetic sample data.",
    "reserved": "Reserved or special-purpose address; not a normal public host.",
}


@dataclass
class IPClassification:
    ip: str
    version: str
    category: str
    is_public: bool
    description: str

    def is_external_candidate(self, allow_documentation: bool = True) -> bool:
        """Could this address be a real outside host? Documentation ranges count only for demo data."""
        return self.is_public or (allow_documentation and self.category == "documentation")


def _norm_ip(value: str):
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def extract_ips(text: str) -> List[str]:
    """Return unique, valid IPv4/IPv6 addresses found in ``text`` in order of appearance."""
    found: List[tuple] = []
    for rx in (_IPV4_RE, _IPV6_RE):
        for m in rx.finditer(text or ""):
            try:
                found.append((m.start(), str(_norm_ip(m.group(0)))))
            except ValueError:
                continue  # e.g. "09:15:03" matches the IPv6 shape but is not an address
    seen, ordered = set(), []
    for _, ip in sorted(found):
        if ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def classify_ip(value: str) -> IPClassification:
    """Classify an address as public / private / loopback / reserved / documentation ..."""
    ip = _norm_ip(value)
    version = f"IPv{ip.version}"
    if ip.is_unspecified:
        cat = "unspecified"
    elif ip.is_loopback:
        cat = "loopback"
    elif ip.is_link_local:
        cat = "link-local"
    elif ip.is_multicast:
        cat = "multicast"
    elif any(ip.version == n.version and ip in n for n in _DOC_NETS):
        cat = "documentation"
    elif ip.is_private and not (ip.version == 4 and ip in _CGNAT):
        cat = "private"
    elif ip.version == 4 and ip in _CGNAT:
        cat = "shared (CGNAT)"
    elif ip.version == 4 and ip in _BENCHMARK:
        cat = "reserved"
    elif ip.is_reserved:
        cat = "reserved"
    elif ip.is_global:
        cat = "public"
    else:
        cat = "reserved"
    return IPClassification(str(ip), version, cat, cat == "public", CATEGORY_NOTES[cat])


# ---------------------------------------------------------------------------
# Received header parsing
# ---------------------------------------------------------------------------
@dataclass
class ReceivedHop:
    index: int = 0                   # 1 = oldest hop
    raw: str = ""
    from_text: str = ""
    helo: str = ""
    rdns: str = ""
    rdns_unknown: bool = False       # server logged "unknown": no reverse DNS for the peer
    from_ip: str = ""
    ips: List[str] = field(default_factory=list)
    by_host: str = ""
    protocol: str = ""
    timestamp: Optional[datetime] = None
    timestamp_raw: str = ""
    link_ok: Optional[bool] = None   # does this hop's 'from' match the previous hop's 'by'?
    link_note: str = ""
    time_ok: Optional[bool] = None   # is the timestamp consistent with the previous hop?
    time_note: str = ""
    delay_seconds: Optional[float] = None

    @property
    def endpoint_label(self) -> str:
        return self.helo or self.rdns or self.from_ip or "unknown"


_WS = re.compile(r"\s+")


def _parse_ts(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_received_header(raw: str) -> ReceivedHop:
    """Extract from/by/with/timestamp details from one Received header (best effort)."""
    text = _WS.sub(" ", raw or "").strip()
    body, ts_raw = text, ""
    if ";" in text:
        body, ts_raw = text.rsplit(";", 1)
    body, ts_raw = body.strip(), ts_raw.strip()

    from_text, remainder = "", body
    if re.match(r"(?i)^from\s", body):
        m = re.match(r"(?is)^from\s+(.*?)\s+by\s+(.*)$", body)
        if m:
            from_text, remainder = m.group(1), "by " + m.group(2)
        else:
            from_text, remainder = body[5:], ""

    by_m = re.search(r"(?i)\bby\s+([^\s;()]+)", remainder)
    by_host = normalize_host(by_m.group(1)) if by_m else ""
    if is_ip_literal(by_host):  # e.g. Gmail's internal "by 2002:a05:..." identifiers
        by_host = ""
    with_m = re.search(r"(?i)\bwith\s+([A-Za-z0-9_-]+)", remainder)

    helo = ""
    m_h = re.search(r"(?i)\b(?:helo|ehlo)[= ]\s*([^\s)\]]+)", from_text)
    if m_h:
        helo = m_h.group(1)
    else:
        tok = re.match(r"^\[?([^\s()\[\]]+)\]?", from_text.strip())
        if tok:
            helo = tok.group(1)
    helo = normalize_host(helo)
    if is_ip_literal(helo):
        helo = ""

    rdns = ""
    m_r = re.search(r"\(\s*([^\s()\[\]=]+)\s+\[", from_text)
    if m_r:
        rdns = m_r.group(1)
    rdns_unknown = rdns.lower() == "unknown"
    rdns = "" if rdns_unknown else normalize_host(rdns)
    if is_ip_literal(rdns):
        rdns = ""

    ips = extract_ips(from_text)
    from_ip = ""
    for m in re.finditer(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", from_text):
        try:
            from_ip = str(_norm_ip(m.group(1)))
            break
        except ValueError:
            continue
    if not from_ip and ips:
        from_ip = ips[0]

    return ReceivedHop(
        raw=raw, from_text=from_text, helo=helo, rdns=rdns, rdns_unknown=rdns_unknown,
        from_ip=from_ip, ips=ips, by_host=by_host,
        protocol=with_m.group(1) if with_m else "",
        timestamp=_parse_ts(ts_raw), timestamp_raw=ts_raw,
    )


def _hosts_match(a: str, b: str) -> bool:
    if not a or not b:
        return False
    if a == b:
        return True
    return "." in a and "." in b and registered_domain(a) == registered_domain(b)


def _check_link(older: ReceivedHop, newer: ReceivedHop):
    """Hop N's 'by' host should be the 'from' host named by hop N+1."""
    names = {n for n in (newer.helo, newer.rdns) if n}
    if not older.by_host or not names:
        return None, "Not enough hostname data to compare with the previous hop."
    if any(_hosts_match(older.by_host, n) for n in names):
        return True, f"Hop {newer.index} names {', '.join(sorted(names))}, matching the previous hop's server {older.by_host}."
    return False, (f"Hop {older.index} was written by '{older.by_host}', but hop {newer.index} says the message "
                   f"came from '{', '.join(sorted(names))}'. The chain does not connect here.")


def build_hops(received_newest_first: Iterable[str]) -> List[ReceivedHop]:
    """Parse Received headers and return hops in chronological order (oldest first)."""
    hops = [parse_received_header(r) for r in reversed(list(received_newest_first))]
    for i, hop in enumerate(hops, 1):
        hop.index = i
    for prev, cur in zip(hops, hops[1:]):
        cur.link_ok, cur.link_note = _check_link(prev, cur)
        if prev.timestamp and cur.timestamp:
            delta = (cur.timestamp - prev.timestamp).total_seconds()
            cur.delay_seconds = delta
            if delta < -300:  # allow 5 minutes of clock skew
                cur.time_ok = False
                cur.time_note = (f"Hop {cur.index} is timestamped {abs(int(delta))} s BEFORE hop {prev.index}, "
                                 "which is not possible in a genuine chain (beyond normal clock skew).")
            else:
                cur.time_ok = True
                if delta > 48 * 3600:
                    cur.time_note = f"Unusually long delay ({int(delta // 3600)} h) between hop {prev.index} and hop {cur.index}."
    return hops


# ---------------------------------------------------------------------------
# Identifying the most likely external sending IP
# ---------------------------------------------------------------------------
@dataclass
class SenderIPResult:
    ip: Optional[str] = None
    confidence: str = "Undetermined"      # "Moderate" | "Low" | "Undetermined" - never "Verified"
    hop_index: Optional[int] = None
    headline: str = ""
    reasons: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    earlier_candidates: List[dict] = field(default_factory=list)
    origin_statement: str = ""


GENERAL_CAVEAT = ("Received headers written before the message reached a server you trust can be forged. "
                  "An observed IP address is evidence, not proof, and does not identify a person.")


def identify_sender_ip(hops: List[ReceivedHop], x_originating_ips: Iterable[str] = (),
                       allow_documentation: bool = True) -> SenderIPResult:
    """Pick the most defensible external IP and explain why (or why none can be chosen)."""
    res = SenderIPResult()
    res.caveats.append(GENERAL_CAVEAT)
    x_ips = list(x_originating_ips)

    if not hops:
        res.headline = "No Received headers - the sending IP cannot be determined."
        res.reasons.append("The message contains no Received headers, so there is no routing evidence to examine.")
        res.origin_statement = "The true originating IP cannot be reliably determined."
        return res

    external = []
    for hop in hops:
        if hop.from_ip:
            try:
                if classify_ip(hop.from_ip).is_external_candidate(allow_documentation):
                    external.append(hop)
            except ValueError:
                pass

    if not external:
        seen = [h.from_ip for h in hops if h.from_ip]
        res.headline = "No external IP address could be identified."
        res.reasons.append(
            "Every IP recorded in the Received headers is private, loopback or otherwise non-public."
            if seen else "None of the Received headers records a connecting IP address.")
        res.origin_statement = "The true originating IP cannot be reliably determined."
        return res

    boundary = external[-1]  # newest hop that names an external IP
    pos = hops.index(boundary)
    res.ip, res.hop_index = boundary.from_ip, boundary.index

    res.reasons.append(
        f"Hop {boundary.index} (written by {boundary.by_host or 'an unnamed server'}) is the newest Received header "
        f"that records an external connecting IP ({boundary.from_ip}). It reflects what the receiving side "
        "observed, so it is more trustworthy than headers further down the chain.")
    internal_after = [h for h in hops[pos + 1:]]
    if internal_after:
        res.reasons.append(f"{len(internal_after)} newer hop(s) only show internal hand-offs inside the receiving infrastructure.")

    # The identified hop itself and every hop after it must connect cleanly and be in time order.
    tail_consistent = all(h.link_ok is not False and h.time_ok is not False for h in hops[pos:])
    complete = bool(boundary.by_host and boundary.timestamp)
    corroborated = len(hops) >= 2

    if not tail_consistent:
        res.confidence = "Low"
        res.caveats.append("The identified hop or a later hop does not connect cleanly with the chain "
                           "(server names or timestamps are inconsistent), which weakens the evidence.")
    elif not complete:
        res.confidence = "Low"
        res.caveats.append("The hop that recorded this IP is missing its server name or timestamp.")
    elif not corroborated:
        res.confidence = "Low"
        res.caveats.append("Only a single Received header is available, so nothing corroborates it.")
    else:
        res.confidence = "Moderate"
        res.reasons.append("The surrounding hops are consistent (server names connect and timestamps are in order).")

    if boundary.rdns_unknown:
        res.caveats.append("The receiving server could not resolve a reverse-DNS name for this IP.")

    if x_ips:
        if res.ip in x_ips:
            res.reasons.append("The X-Originating-IP header names the same address (self-reported, so only weak corroboration).")
        else:
            res.caveats.append(f"X-Originating-IP names {', '.join(x_ips)}, which differs from the identified IP. "
                               "That header is added by the sending system and is unverified.")

    # Earlier external IPs in the chain (lower reliability).
    for j, hop in enumerate(hops[:pos]):
        if not hop.from_ip or hop is boundary:
            continue
        try:
            if not classify_ip(hop.from_ip).is_external_candidate(allow_documentation):
                continue
        except ValueError:
            continue
        connected = all(h.link_ok is not False for h in hops[j + 1:pos + 1])
        res.earlier_candidates.append({
            "ip": hop.from_ip, "hop_index": hop.index,
            "status": ("Earlier hop in a consistent chain - lower reliability" if connected
                       else "Below a chain break - unverified, possibly forged"),
        })

    if boundary.index == 1:
        res.origin_statement = ("This was the first hop in the chain, so the IP is the host that connected directly. "
                                "It may be the sender's own device, a proxy/VPN or a compromised machine - the headers "
                                "cannot say which.")
    else:
        res.origin_statement = ("The identified IP is a mail server or relay that passed the message on. The device "
                                "that originally composed the email cannot be reliably determined from headers alone.")
    res.headline = f"{res.ip} (confidence: {res.confidence})"
    return res


# ---------------------------------------------------------------------------
# IP table
# ---------------------------------------------------------------------------
def reverse_dns(ip: str, timeout: float = 3.0) -> Optional[str]:
    """Optional reverse-DNS lookup with a hard timeout. Sends the IP to your DNS resolver."""
    import socket
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=timeout)
    except (OSError, FutureTimeout, ValueError):
        return None


def build_ip_table(hops: List[ReceivedHop], sender: SenderIPResult, x_originating_ips: Iterable[str] = (),
                   other_sources: Optional[Dict[str, str]] = None, allow_documentation: bool = True,
                   rdns: Optional[Dict[str, str]] = None) -> List[dict]:
    """One row per unique IP, ordered chronologically, with an honest assessment."""
    rows: Dict[str, dict] = {}

    def add(ip: str, seen_in: str, evidence: str):
        try:
            cls = classify_ip(ip)
        except ValueError:
            return
        row = rows.setdefault(cls.ip, {"cls": cls, "seen": [], "evidence": []})
        if seen_in not in row["seen"]:
            row["seen"].append(seen_in)
        if evidence not in row["evidence"]:
            row["evidence"].append(evidence)

    for hop in hops:
        for ip in hop.ips:
            add(ip, f"Received hop {hop.index} (from-clause)", "Written into a Received header by " + (hop.by_host or "an unnamed server"))
    for ip in x_originating_ips:
        add(ip, "X-Originating-IP", "Self-reported by the sending system (unverified)")
    for label, text in (other_sources or {}).items():
        for ip in extract_ips(text):
            add(ip, label, "Mentioned in header text")

    earlier = {c["ip"]: c["status"] for c in sender.earlier_candidates}
    rdns = rdns or {}
    table = []
    for n, (ip, row) in enumerate(rows.items(), 1):
        cls: IPClassification = row["cls"]
        if sender.ip == ip:
            assessment = f"Most likely sending IP - confidence {sender.confidence} (observed, not verified)"
        elif ip in earlier:
            assessment = earlier[ip]
        elif not cls.is_external_candidate(allow_documentation):
            assessment = "Not publicly routable - internal or client-side address"
        elif row["evidence"] == ["Self-reported by the sending system (unverified)"]:
            assessment = "Self-reported only - unverified"
        else:
            assessment = "Observed in headers; not selected as the sender"
        table.append({
            "#": n,
            "IP Address": ip,
            "Version": cls.version,
            "Classification": cls.category,
            "Seen In": "; ".join(row["seen"]),
            "Evidence": "; ".join(row["evidence"]),
            "External Candidate": "Yes" if cls.is_external_candidate(allow_documentation) else "No",
            "Assessment": assessment,
            "Reverse DNS": rdns.get(ip) or "-",
            "Note": cls.description,
        })
    return table


# ---------------------------------------------------------------------------
# Optional IP intelligence (APIs). Only the IP address is ever sent.
# ---------------------------------------------------------------------------
_ENV_LOADED = False


def _load_dotenv() -> None:
    """Tiny .env loader (avoids an extra dependency). Never overrides real environment variables."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    env_path = Path(__file__).resolve().parent.parent / ".env"
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        pass


def intel_configured() -> Dict[str, bool]:
    """Which providers have a key configured (the keys themselves are never returned)."""
    _load_dotenv()
    return {"ipinfo": bool(os.environ.get("IPINFO_TOKEN")),
            "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY"))}


def lookup_ip_intelligence(ip: str, timeout: float = 8.0) -> dict:
    """Look up geolocation/ASN (ipinfo.io) and reputation (AbuseIPDB) for a PUBLIC IP.

    Returns a dict with ``status`` in {"ok", "partial", "error", "not_configured", "skipped"}.
    Nothing is fabricated: missing data stays ``None``.
    """
    result = {"ip": ip, "status": "not_configured", "geolocation": None, "reputation": None, "messages": []}
    try:
        cls = classify_ip(ip)
    except ValueError:
        result["status"] = "skipped"
        result["messages"].append("Not a valid IP address.")
        return result
    if not cls.is_public:
        result["status"] = "skipped"
        result["messages"].append(f"Not queried: {ip} is a {cls.category} address, so no public intelligence exists for it.")
        return result

    cfg = intel_configured()
    if not any(cfg.values()):
        result["messages"].append(
            "No IP intelligence API is configured. Set IPINFO_TOKEN and/or ABUSEIPDB_API_KEY in your .env file. "
            "No location or reputation data is shown because none was retrieved.")
        return result

    attempted = succeeded = 0
    if cfg["ipinfo"]:
        attempted += 1
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout,
                             headers={"Authorization": f"Bearer {os.environ['IPINFO_TOKEN']}", "Accept": "application/json"})
            if r.status_code == 200:
                d = r.json()
                org = d.get("org") or ""
                m = re.match(r"^(AS\d+)\s*(.*)$", org)
                result["geolocation"] = {
                    "city": d.get("city"), "region": d.get("region"), "country": d.get("country"),
                    "organization": (m.group(2) if m else org) or None,
                    "asn": m.group(1) if m else None,
                    "hostname": d.get("hostname"), "source": "ipinfo.io",
                }
                succeeded += 1
            else:
                result["messages"].append(f"ipinfo.io returned HTTP {r.status_code}.")
        except (requests.RequestException, ValueError) as exc:
            result["messages"].append(f"ipinfo.io lookup failed ({type(exc).__name__}).")
    if cfg["abuseipdb"]:
        attempted += 1
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check", timeout=timeout,
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             headers={"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"})
            if r.status_code == 200:
                d = r.json().get("data", {})
                result["reputation"] = {
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "total_reports": d.get("totalReports"),
                    "isp": d.get("isp"), "usage_type": d.get("usageType"),
                    "country_code": d.get("countryCode"), "domain": d.get("domain"),
                    "source": "AbuseIPDB (last 90 days)",
                }
                succeeded += 1
            else:
                result["messages"].append(f"AbuseIPDB returned HTTP {r.status_code}.")
        except (requests.RequestException, ValueError) as exc:
            result["messages"].append(f"AbuseIPDB lookup failed ({type(exc).__name__}).")

    result["status"] = "ok" if succeeded == attempted else ("partial" if succeeded else "error")
    return result


GEO_DISCLAIMER = ("IP geolocation is approximate (often city- or country-level and sometimes wrong). "
                  "It shows where an address is registered or routed, not who sent the email or where "
                  "that person physically is.")
