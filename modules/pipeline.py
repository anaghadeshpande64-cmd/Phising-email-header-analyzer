"""Glue code: run every analysis step on a parsed email and bundle the results."""
from __future__ import annotations

from typing import Dict, Optional

from .authentication_checker import analyze_authentication
from .email_parser import ParsedEmail
from .ip_analyzer import build_hops, build_ip_table, identify_sender_ip, lookup_ip_intelligence, reverse_dns
from .phishing_detector import detect_indicators
from .risk_assessment import assess_risk


def analyze_email(parsed: ParsedEmail, use_intel: bool = False, use_rdns: bool = False,
                  protected_domains: Optional[Dict[str, list]] = None,
                  intel: Optional[dict] = None) -> dict:
    """Run the whole investigation.

    ``use_intel`` / ``use_rdns`` are opt-in because they send the *IP address only*
    (never the email) to external services / your DNS resolver.
    """
    hops = build_hops(parsed.received)
    sender = identify_sender_ip(hops, parsed.x_originating_ip)
    auth = analyze_authentication(parsed.authentication_results, parsed.received_spf,
                                  parsed.dkim_signatures, parsed.from_domain)

    # ``intel`` may be supplied by the caller (e.g. cached by the UI); otherwise look it up if requested.
    if intel is None and use_intel and sender.ip:
        intel = lookup_ip_intelligence(sender.ip)
    rdns = {}
    if use_rdns:
        tmp = build_ip_table(hops, sender, parsed.x_originating_ip)
        for row in tmp:
            if row["Classification"] == "public":  # only public addresses are queried
                name = reverse_dns(row["IP Address"])
                if name:
                    rdns[row["IP Address"]] = name
    ip_table = build_ip_table(
        hops, sender, parsed.x_originating_ip,
        other_sources={"Return-Path": parsed.return_path_raw, "Received-SPF": " ".join(parsed.received_spf)},
        rdns=rdns)

    indicators = detect_indicators(parsed, hops, sender, auth, intel, protected_domains)
    risk = assess_risk(indicators, auth)
    return {"parsed": parsed, "hops": hops, "sender": sender, "auth": auth, "ip_table": ip_table,
            "intel": intel, "indicators": indicators, "risk": risk}
