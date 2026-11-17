"""PDF report generation (ReportLab). Returns bytes; optionally saves into ``reports/``."""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .ip_analyzer import GEO_DISCLAIMER

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
LEVEL_COLORS = {"LOW RISK": "#1a7f4b", "MEDIUM RISK": "#b7791f", "HIGH RISK": "#c0392b"}
STATUS_COLORS = {"PASS": "#1a7f4b", "FAIL": "#c0392b", "NONE": "#b7791f", "UNKNOWN": "#5f6b7a"}


def _p(text, style) -> Paragraph:
    """Paragraph from untrusted text: control chars removed and XML-escaped."""
    clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text if text is not None else ""))
    return Paragraph(escape(clean), style)


def _table(rows, widths, styles, header=True, repeat=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if (header and repeat) else 0)
    base = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c5ccd6")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        base += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1e33")),
                 ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(base + styles))
    return t


def generate_pdf_report(result: dict, save: bool = False, filename: Optional[str] = None) -> bytes:
    """Build the investigation report from ``pipeline.analyze_email`` output."""
    parsed, sender, auth, risk = result["parsed"], result["sender"], result["auth"], result["risk"]
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5)
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=10)
    cellw = ParagraphStyle("cellw", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontSize=20, textColor=colors.HexColor("#0b1e33"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12.5, textColor=colors.HexColor("#0b1e33"),
                        spaceBefore=10, spaceAfter=4)
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=7, leading=8.5)
    center = ParagraphStyle("center", parent=body, alignment=TA_CENTER)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm,
                            title="Phishing Email Header Analysis Report", author="Phishing Email Header Analyzer")
    W = A4[0] - 32 * mm
    story = []

    story.append(Paragraph("Phishing Email Header Analysis Report", h1))
    story.append(_p(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  |  Source: {parsed.source_name}", center))
    story.append(Spacer(1, 4))
    story.append(_p("Educational email-forensics output. " + risk["disclaimer"], small))

    # 1. Risk assessment
    story.append(Paragraph("1. Risk assessment", h2))
    colr = LEVEL_COLORS.get(risk["level"], "#333333")
    story.append(Paragraph(f'<font color="{colr}"><b>{escape(risk["level"])}</b></font> &nbsp; score {risk["score"]}/100 '
                           f'<font size="8">(scale: {escape(risk["scale"])})</font>', body))
    story.append(_p(risk["summary"], body))
    if risk["factors"]:
        rows = [[_p("Contributing factor", cellw), _p("Severity", cellw), _p("Points", cellw)]]
        rows += [[_p(f["factor"], cell), _p(f["severity"].upper(), cell), _p(f["points"], cell)] for f in risk["factors"]]
        story.append(Spacer(1, 3))
        story.append(_table(rows, [W * 0.68, W * 0.18, W * 0.14], []))
    for pos in risk["positives"]:
        story.append(_p("+ " + pos, small))

    # 2. Metadata
    story.append(Paragraph("2. Email metadata", h2))
    rows = [[_p(k, ParagraphStyle("k", parent=cell, fontName="Helvetica-Bold")), _p(v, cell)] for k, v in parsed.metadata_rows()]
    story.append(_table(rows, [W * 0.25, W * 0.75], [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f7"))], header=False))
    if parsed.attachments:
        story.append(Spacer(1, 3))
        story.append(_p("Attachments (listed only, never opened): " + "; ".join(
            f"{a['filename']} [{a['content_type']}]" + (" RISKY TYPE" if a["risky_extension"] else "") for a in parsed.attachments), small))

    # 3. Authentication
    story.append(Paragraph("3. SPF, DKIM and DMARC", h2))
    rows = [[_p(x, cellw) for x in ("Mechanism", "Result", "Raw value", "Domain", "Source / detail")]]
    styles = []
    for i, key in enumerate(("spf", "dkim", "dmarc"), 1):
        a = auth[key]
        rows.append([_p(a.mechanism, cell), _p(a.status, cell), _p(a.raw_result or "-", cell), _p(a.domain or "-", cell),
                     _p(a.source + (f" - {a.detail}" if a.detail else ""), cell)])
        styles.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(STATUS_COLORS[a.status])))
    story.append(_table(rows, [W * 0.1, W * 0.1, W * 0.12, W * 0.2, W * 0.48], styles))
    for n in auth["notes"]:
        story.append(_p("Note: " + n, small))

    # 4. Sender IP analysis
    story.append(Paragraph("4. Sender IP analysis", h2))
    story.append(_p(f"Most likely external sending IP: {sender.headline}", body))
    for r in sender.reasons:
        story.append(_p("Why: " + r, small))
    for c in sender.caveats:
        story.append(_p("Caveat: " + c, small))
    story.append(_p(sender.origin_statement, small))
    story.append(Spacer(1, 4))
    rows = [[_p(x, cellw) for x in ("IP", "Class", "Seen in", "Assessment")]]
    for r in result["ip_table"]:
        rows.append([_p(r["IP Address"], cell), _p(r["Classification"], cell), _p(r["Seen In"], cell), _p(r["Assessment"], cell)])
    story.append(_table(rows, [W * 0.18, W * 0.14, W * 0.3, W * 0.38], []))
    intel = result.get("intel")
    story.append(Spacer(1, 3))
    if intel and intel["status"] in ("ok", "partial"):
        for label, d in (("Geolocation", intel.get("geolocation")), ("Reputation", intel.get("reputation"))):
            if d:
                story.append(_p(f"{label}: " + ", ".join(f"{k}={v}" for k, v in d.items() if v not in (None, "")), small))
    else:
        story.append(_p("IP intelligence: not retrieved" + (f" ({'; '.join(intel['messages'])})" if intel else " (lookup not requested)")
                        + ". No location or reputation data is shown.", small))
    story.append(_p(GEO_DISCLAIMER, small))

    # 5. Routing path
    story.append(Paragraph("5. Routing path (oldest hop first)", h2))
    if result["hops"]:
        rows = [[_p(x, cellw) for x in ("Hop", "From (claimed / observed)", "By", "Time", "Consistency")]]
        for h in result["hops"]:
            flags = [n for n in (h.link_note if h.link_ok is False else "", h.time_note if h.time_ok is False else "") if n]
            rows.append([_p(h.index, cell), _p(f"{h.endpoint_label} [{h.from_ip or 'no IP'}]", cell), _p(h.by_host or "-", cell),
                         _p(h.timestamp_raw or "-", cell), _p(" ".join(flags) or "OK / not comparable", cell)])
        story.append(_table(rows, [W * 0.06, W * 0.3, W * 0.2, W * 0.2, W * 0.24], []))
    else:
        story.append(_p("No Received headers present.", body))

    # 6. Indicators
    story.append(Paragraph("6. Phishing indicators", h2))
    if result["indicators"]:
        for ind in result["indicators"]:
            story.append(KeepTogether([
                Paragraph(f"<b>[{ind['severity'].upper()}]</b> {escape(ind['title'])} <font size='7'>(+{ind['points']})</font>", body),
                _p(ind["explanation"], small),
                _p("Evidence: " + ind["evidence"], small) if ind["evidence"] else Spacer(1, 0),
                Spacer(1, 3)]))
    else:
        story.append(_p("No indicators were detected by this tool's rules.", body))

    # 7. Summary
    story.append(Paragraph("7. Investigation summary", h2))
    summary = (f"The message from '{parsed.from_addr or 'unknown sender'}' was assessed as {risk['level']} "
               f"(score {risk['score']}/100). SPF={auth['spf'].status}, DKIM={auth['dkim'].status}, DMARC={auth['dmarc'].status}. "
               f"{sender.origin_statement} ")
    story.append(_p(summary, body))
    story.append(_p("Limitations: Received headers added before the first trusted server can be forged; IP addresses are observed, "
                    "not verified, and never identify a person; authentication results are copied from headers, not re-verified.", small))

    # 8. Raw headers
    story.append(Paragraph("8. Raw headers (as received, truncated at 12,000 characters)", h2))
    raw = parsed.raw_headers[:12000]
    for line in raw.split("\n"):
        story.append(_p(line.replace("\t", "    ") or " ", mono))

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5f6b7a"))
        canvas.drawString(16 * mm, 9 * mm, "Investigative assessment only - not definitive phishing detection.")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    data = buf.getvalue()
    if save:
        REPORTS_DIR.mkdir(exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        (REPORTS_DIR / safe).write_bytes(data)
    return data
