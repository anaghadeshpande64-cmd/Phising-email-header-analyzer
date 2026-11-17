"""Transparent, additive risk scoring.

score = sum of indicator points (capped at 100).
    0-24  -> LOW RISK
   25-54  -> MEDIUM RISK
   55+    -> HIGH RISK

It is an *investigative assessment*, not a verdict: legitimate mail can score
above zero and carefully crafted phishing can score zero.
"""
from __future__ import annotations

from typing import Dict, List

LOW_MAX = 24
MEDIUM_MAX = 54

DISCLAIMER = ("This is a rule-based investigative assessment, not definitive phishing detection. "
              "It only examines headers; it does not inspect links, message content or attachments, and it "
              "cannot prove or rule out malicious intent. Verify suspicious messages through another channel.")


def level_for(score: int) -> str:
    if score <= LOW_MAX:
        return "LOW RISK"
    if score <= MEDIUM_MAX:
        return "MEDIUM RISK"
    return "HIGH RISK"


def assess_risk(indicators: List[dict], auth: Dict[str, object]) -> dict:
    """Return score, level, contributing factors and mitigating observations."""
    total = sum(i["points"] for i in indicators)
    score = min(100, total)
    level = level_for(score)

    factors = [{"factor": i["title"], "points": i["points"], "severity": i["severity"]}
               for i in sorted(indicators, key=lambda i: -i["points"]) if i["points"] > 0]

    positives: List[str] = []
    for key in ("spf", "dkim", "dmarc"):
        if auth[key].status == "PASS":
            positives.append(f"{auth[key].mechanism} passed according to {auth[key].source}.")

    if not indicators:
        summary = "No suspicious indicators were detected by the rules in this tool."
    else:
        top = ", ".join(f["factor"].lower() for f in factors[:3])
        summary = f"Score {score}/100 driven mainly by: {top}."
    if level == "LOW RISK":
        summary += " Low risk does not mean safe - treat unexpected requests with care."

    return {"score": score, "level": level, "factors": factors, "positives": positives,
            "summary": summary, "disclaimer": DISCLAIMER,
            "scale": "0-24 low, 25-54 medium, 55-100 high"}
