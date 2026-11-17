"""Rule-based phishing indicator detection.

Every indicator carries a severity, a point value used by ``risk_assessment`` and a
plain-language explanation of *why* it may be suspicious. None of these rules is proof
of phishing on its own - legitimate mail also trips some of them (mailing lists,
forwarding, newsletters sent through third-party services).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .domain_utils import (
    domain_labels_without_suffix, has_mixed_scripts, is_under, levenshtein,
    registered_domain, skeleton_variants,
)
from .email_parser import ParsedEmail
from .ip_analyzer import ReceivedHop, SenderIPResult, classify_ip

# Brands commonly impersonated, with their genuine domains. "examplebank" is the fictional
# brand used by the bundled synthetic samples. Extend via the ``protected_domains`` argument.
KNOWN_BRANDS: Dict[str, List[str]] = {
    "examplebank": ["examplebank.example"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "whatsapp": ["whatsapp.com"],
}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "gq", "tk", "ml", "cf", "ga",
                   "icu", "buzz", "rest", "country", "kim", "loan", "men", "stream", "download"}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Indicator:
    code: str
    title: str
    severity: str          # high | medium | low | info
    points: int
    explanation: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {"code": self.code, "title": self.title, "severity": self.severity,
                "points": self.points, "explanation": self.explanation, "evidence": self.evidence}


def _brand_check(domain: str, protected: Dict[str, List[str]]) -> Optional[dict]:
    """Does ``domain`` imitate a protected brand without being one of its real domains?"""
    reg = registered_domain(domain)
    if not reg:
        return None
    for brand, officials in protected.items():
        if any(is_under(domain, o) for o in officials):
            return None  # genuinely belongs to the brand
    labels = domain_labels_without_suffix(reg) or [reg]
    sld = labels[-1]
    sld_variants = skeleton_variants(sld)
    for brand, officials in protected.items():
        b = brand.lower()
        if any(v == b for v in sld_variants) and sld != b:
            return {"brand": brand, "kind": "look-alike characters", "official": officials}
        if len(b) >= 5 and sld != b and any(0 < levenshtein(v, b) <= 1 for v in sld_variants):
            return {"brand": brand, "kind": "typo-squatting (one character different)", "official": officials}
        # Brand name embedded in a longer, unrelated name (paypal-secure-login.com, secure.paypal.evil.com)
        joined = ".".join(domain_labels_without_suffix(normalize(domain)))
        if len(b) >= 4 and any(b in v for v in skeleton_variants(joined)):
            return {"brand": brand, "kind": "brand name inside an unrelated domain", "official": officials}
    return None


def normalize(host: str) -> str:
    return (host or "").strip().lower()


def detect_indicators(parsed: ParsedEmail, hops: List[ReceivedHop], sender: SenderIPResult,
                      auth: Dict[str, object], intel: Optional[dict] = None,
                      protected_domains: Optional[Dict[str, List[str]]] = None) -> List[dict]:
    """Run all rules and return indicators sorted by severity."""
    protected = dict(KNOWN_BRANDS)
    protected.update({k.lower(): [d.lower() for d in v] for k, v in (protected_domains or {}).items()})
    out: List[Indicator] = []
    add = out.append

    from_dom = registered_domain(parsed.from_domain)

    # --- sender / identity checks -------------------------------------------------
    if not parsed.from_addr:
        add(Indicator("no_from", "Missing or unparsable From address", "medium", 15,
                      "Legitimate mail almost always has a valid sender address.", parsed.from_raw or "(none)"))
    if parsed.from_count > 1:
        add(Indicator("multi_from", "Multiple From headers", "high", 25,
                      "Duplicate From headers are used to show one sender to the user while another is processed.",
                      f"{parsed.from_count} From headers"))

    if parsed.reply_to_addrs:
        rt_doms = {registered_domain(a.rsplit("@", 1)[-1]) for a in parsed.reply_to_addrs if "@" in a}
        if from_dom and rt_doms and from_dom not in rt_doms:
            add(Indicator("reply_to_mismatch", "From and Reply-To domains differ", "medium", 20,
                          "Replies would go to a different domain than the one displayed as the sender - a common "
                          "tactic to harvest replies. (Some legitimate services use separate support domains.)",
                          f"From: {parsed.from_domain} | Reply-To: {', '.join(parsed.reply_to_addrs)}"))

    if parsed.return_path_addr and from_dom:
        rp_dom = registered_domain(parsed.return_path_addr.rsplit("@", 1)[-1])
        if rp_dom and rp_dom != from_dom:
            add(Indicator("return_path_mismatch", "Return-Path domain differs from From domain", "low", 8,
                          "The envelope sender (bounce address) belongs to a different domain than the visible sender. "
                          "This is normal for bulk-mail providers but also typical of spoofed mail.",
                          f"From: {parsed.from_domain} | Return-Path: {parsed.return_path_addr}"))

    if parsed.message_id_domain and from_dom:
        mid = registered_domain(parsed.message_id_domain)
        if mid and mid != from_dom:
            add(Indicator("msgid_mismatch", "Message-ID domain differs from From domain", "low", 5,
                          "Message-IDs are normally generated by the sender's own mail system; a different domain "
                          "can indicate a third-party service or a forged header.",
                          f"Message-ID domain: {parsed.message_id_domain}"))

    # --- domain impersonation ---------------------------------------------------
    domains_to_check = {"From": parsed.from_domain}
    for a in parsed.reply_to_addrs:
        if "@" in a:
            domains_to_check["Reply-To"] = a.rsplit("@", 1)[-1]
    flagged = set()
    for where, dom in domains_to_check.items():
        if not dom or dom in flagged:
            continue
        hit = _brand_check(dom, protected)
        if hit:
            flagged.add(dom)
            add(Indicator("brand_impersonation", f"Possible impersonation of '{hit['brand']}' ({where} domain)", "high", 30,
                          f"The domain '{dom}' resembles '{hit['brand']}' via {hit['kind']} but is not one of its known "
                          f"domains ({', '.join(hit['official'])}). Look-alike domains are a core phishing technique.",
                          dom))
        if dom.startswith("xn--") or ".xn--" in dom:
            add(Indicator("punycode", f"Internationalised (punycode) {where} domain", "medium", 15,
                          "Punycode domains can hide visually identical look-alike characters from other alphabets.", dom))
        if has_mixed_scripts(dom):
            add(Indicator("mixed_scripts", f"{where} domain mixes alphabets", "high", 25,
                          "Mixing Latin with Cyrillic/Greek letters is a homograph-attack technique.", dom))
        tld = dom.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            add(Indicator("suspicious_tld", f"{where} domain uses a TLD frequently abused for spam", "low", 8,
                          f"The '.{tld}' top-level domain is cheap or free and over-represented in abuse reports. "
                          "Many legitimate sites use it too.", dom))
        sld_labels = domain_labels_without_suffix(registered_domain(dom))
        sld = sld_labels[-1] if sld_labels else ""
        if sld.count("-") >= 2 or sum(c.isdigit() for c in sld) >= 3:
            add(Indicator("odd_domain_shape", f"{where} domain looks machine-generated or keyword-stuffed", "low", 6,
                          "Many hyphens or digits in a domain name are common in throw-away phishing domains.", dom))

    # Display name claims a different address or brand.
    name = parsed.from_name.lower()
    if name and "@" in name:
        claimed = name.split("@")[-1].strip(" <>")
        if claimed and registered_domain(claimed) != from_dom:
            add(Indicator("display_name_spoof", "Display name contains a different email address", "high", 25,
                          "Mail apps often show only the display name. Putting another address in it is a classic spoofing trick.",
                          parsed.from_raw))
    elif name and not flagged:  # skip when the domain was already flagged as impersonation
        for brand, officials in protected.items():
            if brand in name.replace(" ", "") and not any(is_under(parsed.from_domain, o) for o in officials):
                add(Indicator("display_name_brand", f"Display name mentions '{brand}' but the domain is not theirs", "medium", 15,
                              "The visible name suggests a well-known organisation while the sending domain is unrelated.",
                              parsed.from_raw))
                break

    # --- authentication ---------------------------------------------------------
    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]
    for res, pts in ((spf, 20), (dkim, 15), (dmarc, 25)):
        if res.status == "FAIL":
            why = {
                "SPF": "The sending server was not authorised by the domain's SPF record (or was explicitly rejected). "
                       "'softfail' means the domain owner says the IP is probably not allowed.",
                "DKIM": "The cryptographic signature did not verify, so the message may have been altered or signed by someone else.",
                "DMARC": "The message failed the domain owner's published policy: neither aligned SPF nor aligned DKIM passed.",
            }[res.mechanism]
            add(Indicator(f"{res.mechanism.lower()}_fail", f"{res.mechanism} check failed", "high", pts, why,
                          f"{res.mechanism}={res.raw_result} ({res.source})"))
    if not auth["has_auth_results_header"] and not any(r.status != "UNKNOWN" for r in (spf, dkim, dmarc)):
        add(Indicator("no_auth_info", "No authentication results available", "medium", 20,
                      "No Authentication-Results header was found, so SPF/DKIM/DMARC outcomes are unknown. Absence of "
                      "evidence is not a pass: the message may come from a server that does not authenticate, or the "
                      "header was stripped.", "Authentication-Results missing"))
    else:
        unknown = [r.mechanism for r in (spf, dkim, dmarc) if r.status == "UNKNOWN"]
        none = [r.mechanism for r in (spf, dkim, dmarc) if r.status == "NONE"]
        if unknown and auth["has_auth_results_header"]:
            add(Indicator("partial_auth", "Some authentication results are missing", "low", 8,
                          "The receiving server recorded no verdict for: " + ", ".join(unknown) + ". They are treated as unknown, not as passed.",
                          ", ".join(unknown)))
        if none:
            add(Indicator("auth_none", "Sender publishes no policy for: " + ", ".join(none), "low", 8,
                          "'None' means the domain has no such record or no signature, so the receiver could not "
                          "verify the sender for that mechanism.", ", ".join(none)))

    # Alignment: a passing SPF/DKIM for a *different* domain does not authenticate the visible From.
    if from_dom and dmarc.status != "PASS":
        misaligned = []
        if spf.status == "PASS" and spf.domain and registered_domain(spf.domain) != from_dom:
            misaligned.append(f"SPF authenticated {spf.domain}")
        if dkim.status == "PASS" and dkim.domain and registered_domain(dkim.domain) != from_dom:
            misaligned.append(f"DKIM signed by {dkim.domain}")
        if misaligned:
            add(Indicator("misaligned_auth", "Authentication passed for a different domain than From", "medium", 15,
                          "Attackers can pass SPF/DKIM with their own domain while showing someone else's address in From. "
                          "DMARC requires alignment to prevent this.", "; ".join(misaligned) + f"; From domain is {parsed.from_domain}"))

    # --- Received chain ---------------------------------------------------------
    if not hops:
        add(Indicator("no_received", "No Received headers", "medium", 15,
                      "Every mail server adds a Received header; a message without any has been stripped or was "
                      "constructed by hand, leaving no routing evidence.", "0 Received headers"))
    else:
        breaks = [h for h in hops if h.link_ok is False]
        if breaks:
            add(Indicator("chain_break", "Received chain does not connect", "medium", 15,
                          "A hop's 'from' server should match the previous hop's 'by' server. Gaps can mean forged "
                          "or injected headers (or unusual internal relaying).",
                          " | ".join(h.link_note for h in breaks[:2])))
        backwards = [h for h in hops if h.time_ok is False]
        if backwards:
            add(Indicator("time_inconsistent", "Received timestamps are out of order", "medium", 15,
                          "Timestamps should only move forward along the route. Large reversals suggest forged headers or "
                          "badly misconfigured clocks.", " | ".join(h.time_note for h in backwards[:2])))
        if any(h.timestamp is None for h in hops):
            add(Indicator("missing_timestamp", "A Received header has no readable timestamp", "low", 5,
                          "Genuine mail servers always record a date; its absence or corruption is unusual.",
                          f"{sum(1 for h in hops if h.timestamp is None)} hop(s)"))
        if parsed.date_dt and hops[0].timestamp and parsed.date_dt < hops[0].timestamp:
            gap = (hops[0].timestamp - parsed.date_dt).total_seconds()
            if gap > 3 * 86400:
                add(Indicator("old_date", "Date header is far earlier than first delivery", "low", 5,
                              "The message claims to have been written days before it entered the mail system.",
                              f"{int(gap // 86400)} days"))
        if parsed.date_dt and hops[-1].timestamp:
            if (parsed.date_dt - hops[-1].timestamp).total_seconds() > 86400:
                add(Indicator("future_date", "Date header is in the future relative to delivery", "low", 8,
                              "A sending date later than the final delivery time indicates a forged or wrong Date header.",
                              parsed.date_raw))
        boundary = next((h for h in hops if h.index == sender.hop_index), None)
        if boundary:
            if boundary.rdns_unknown:
                add(Indicator("no_rdns", "Sending IP has no reverse DNS", "low", 5,
                              "Legitimate mail servers normally have a reverse-DNS name; its absence is common for "
                              "compromised hosts and bulk-sending malware.", boundary.from_ip))
            if boundary.helo and boundary.rdns and registered_domain(boundary.helo) != registered_domain(boundary.rdns):
                add(Indicator("helo_rdns_mismatch", "Server HELO name does not match its reverse DNS", "low", 5,
                              "The connecting machine announced one identity while DNS says another.",
                              f"HELO {boundary.helo} vs rDNS {boundary.rdns}"))

    # --- sender IP / intelligence ----------------------------------------------------
    if sender.ip is None:
        add(Indicator("origin_unknown", "Origin could not be determined", "low", 5,
                      "No usable external IP was found, so the route gives no evidence about where the message came from.",
                      sender.headline))
    else:
        if parsed.x_originating_ip and sender.ip not in parsed.x_originating_ip:
            add(Indicator("xoip_differs", "X-Originating-IP differs from the identified sending IP", "low", 5,
                          "This sender-supplied header names a different host than the one observed by the receiver.",
                          ", ".join(parsed.x_originating_ip)))
    rep = (intel or {}).get("reputation") if intel else None
    if rep and isinstance(rep.get("abuse_confidence_score"), (int, float)):
        score = rep["abuse_confidence_score"]
        if score >= 50:
            add(Indicator("ip_reputation_bad", "Sending IP has a poor abuse reputation", "high", 25,
                          f"AbuseIPDB rates this address {score}/100 abuse confidence ({rep.get('total_reports')} reports in 90 days).",
                          sender.ip or ""))
        elif score >= 25:
            add(Indicator("ip_reputation_mixed", "Sending IP has some abuse reports", "medium", 10,
                          f"AbuseIPDB abuse confidence is {score}/100.", sender.ip or ""))

    # --- attachments ------------------------------------------------------------
    for att in parsed.attachments:
        if att.get("double_extension"):
            add(Indicator("double_ext", "Attachment with double extension", "high", 25,
                          "Names like 'invoice.pdf.exe' disguise executables as documents.", att["filename"]))
        elif att.get("risky_extension"):
            add(Indicator("risky_attachment", "Attachment with a risky file type", "medium", 15,
                          "This file type can run code or load remote content. It was NOT opened by this tool.", att["filename"]))

    for w in parsed.warnings:
        if "more than one From" not in w:
            add(Indicator("parser_warning", "Header structure warning", "low", 3, w, w))

    out.sort(key=lambda i: (SEVERITY_ORDER[i.severity], -i.points))
    return [i.as_dict() for i in out]
