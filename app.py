"""Phishing Email Header Analyzer - Streamlit dashboard.

Run with:  streamlit run app.py
"""
from __future__ import annotations

import html
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from modules.email_parser import EmailParseError, parse_eml_bytes, parse_raw_text
from modules.ip_analyzer import GEO_DISCLAIMER, intel_configured, lookup_ip_intelligence
from modules.pipeline import analyze_email
from modules.report_generator import generate_pdf_report

BASE = Path(__file__).resolve().parent
SAMPLES = {
    "Legitimate email (all authentication passes)": "legitimate_email.eml",
    "Phishing email (failed authentication, look-alike domain)": "phishing_email.eml",
    "Suspicious email (incomplete authentication headers)": "suspicious_email.eml",
}

st.set_page_config(page_title="Phishing Email Header Analyzer", page_icon="🛡️", layout="wide")

try:
    st.markdown(f"<style>{(BASE / 'assets' / 'style.css').read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)
except OSError:
    pass  # styling is optional


def esc(value) -> str:
    """Escape untrusted text before placing it inside HTML."""
    return html.escape(str(value if value is not None else ""))


def card(label: str, value: str, sub: str = "", css: str = "") -> str:
    return (f'<div class="card {css}"><div class="label">{esc(label)}</div>'
            f'<div class="value">{esc(value)}</div><div class="sub">{esc(sub)}</div></div>')


@st.cache_data(ttl=3600, show_spinner=False)
def cached_intel(ip: str) -> dict:
    return lookup_ip_intelligence(ip)


# --------------------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("### 🛡️ Input")
    mode = st.radio("Choose an input method", ["Sample email", "Upload .eml file", "Paste raw headers"], index=0)
    parsed, error = None, None
    try:
        if mode == "Sample email":
            choice = st.selectbox("Sample", list(SAMPLES))
            parsed = parse_eml_bytes((BASE / "samples" / SAMPLES[choice]).read_bytes(), SAMPLES[choice])
            st.caption("Synthetic data: fictional domains and reserved documentation IPs. Works offline.")
        elif mode == "Upload .eml file":
            up = st.file_uploader("Upload a suspicious email (.eml)", type=["eml", "txt"])
            if up is not None:
                parsed = parse_eml_bytes(up.getvalue(), up.name)
            st.caption("The file is parsed locally. Attachments are never opened or executed.")
        else:
            text = st.text_area("Paste raw email headers (or the full message source)", height=260,
                                placeholder="Received: from ...\nFrom: ...\nAuthentication-Results: ...")
            if text.strip():
                parsed = parse_raw_text(text)
    except EmailParseError as exc:
        error = str(exc)
    except Exception as exc:  # never let a malformed file crash the app
        error = f"Unexpected problem reading the input ({type(exc).__name__})."

    st.markdown("---")
    st.markdown("### Optional lookups")
    cfg = intel_configured()
    use_intel = st.checkbox("IP intelligence (geolocation / reputation)", value=False,
                            help="Sends ONLY the identified public IP address to ipinfo.io / AbuseIPDB. Never the email.")
    st.caption("API keys configured: " + (", ".join(k for k, v in cfg.items() if v) or "none") +
               ". Set keys in a local .env file (see .env.example).")
    use_rdns = st.checkbox("Reverse-DNS lookups", value=False,
                           help="Sends public IPs to your system DNS resolver.")
    st.markdown("---")
    st.caption("Privacy: uploaded emails are never sent to third-party services.")

# --------------------------------------------------------------------------- header
st.markdown('<div class="hero"><div class="tag">Email forensics · Sender IP investigation</div>'
            '<h1>Phishing Email Header Analyzer</h1>'
            '<p>Inspect headers, routing, SPF/DKIM/DMARC and phishing indicators. Results are an '
            'investigative assessment, not a verdict.</p></div>', unsafe_allow_html=True)

if error:
    st.error(f"Could not analyse the input: {error}")
    st.stop()
if parsed is None:
    st.info("Pick a sample, upload an .eml file or paste headers in the sidebar to begin.")
    st.stop()

# --------------------------------------------------------------------------- analysis
result = analyze_email(parsed, use_rdns=use_rdns)
if use_intel and result["sender"].ip:
    result = analyze_email(parsed, use_rdns=use_rdns, intel=cached_intel(result["sender"].ip))
sender, auth, risk, hops = result["sender"], result["auth"], result["risk"], result["hops"]

for w in parsed.warnings:
    st.warning(w)

tabs = st.tabs(["📊 Overview", "🧾 Headers", "🌐 IP investigation", "🛰️ Routing path", "⚠️ Indicators", "📄 Report"])

# --- Overview ---
with tabs[0]:
    c1, c2, c3 = st.columns([1.1, 1.4, 1.5])
    level_css = "risk-" + risk["level"].split()[0]
    c1.markdown(card("Phishing risk assessment", risk["level"], f"Score {risk['score']}/100", level_css), unsafe_allow_html=True)
    c2.markdown(card("Sender", parsed.from_addr or "(unknown)", parsed.from_name or parsed.from_raw, "compact"), unsafe_allow_html=True)
    c3.markdown(card("Most likely external sending IP", sender.ip or "Undetermined",
                     f"Confidence: {sender.confidence} - observed, not verified", "compact"), unsafe_allow_html=True)
    st.write("")
    a1, a2, a3 = st.columns(3)
    for col, key in zip((a1, a2, a3), ("spf", "dkim", "dmarc")):
        r = auth[key]
        sub = (f"{r.raw_result} · {r.domain}" if r.raw_result and r.domain else r.raw_result or r.source)
        col.markdown(card(r.mechanism, r.status, sub, "status-" + r.status), unsafe_allow_html=True)
    st.write("")
    g, f = st.columns([1, 1.4])
    with g:
        color = {"LOW RISK": "#2ecc71", "MEDIUM RISK": "#f5b942", "HIGH RISK": "#ff5c5c"}[risk["level"]]
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=risk["score"], number={"font": {"color": color}},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": color}, "bgcolor": "#111c2e",
                   "steps": [{"range": [0, 24], "color": "#12351f"}, {"range": [24, 54], "color": "#3a3014"},
                             {"range": [54, 100], "color": "#3a1818"}]}))
        fig.update_layout(height=250, margin=dict(l=20, r=20, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)",
                          font={"color": "#e6edf6"}, title={"text": "Risk score", "font": {"size": 14}})
        st.plotly_chart(fig, width="stretch")
    with f:
        st.markdown("**Why this score**")
        st.write(risk["summary"])
        if risk["factors"]:
            df = pd.DataFrame(risk["factors"]).rename(columns={"factor": "Factor", "points": "Points", "severity": "Severity"})
            bar = go.Figure(go.Bar(x=df["Points"][::-1], y=df["Factor"][::-1], orientation="h", marker_color="#36d1dc"))
            bar.update_layout(height=max(180, 28 * len(df) + 60), margin=dict(l=10, r=10, t=10, b=10),
                              paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e6edf6"},
                              xaxis_title="Points")
            st.plotly_chart(bar, width="stretch")
        for p in risk["positives"]:
            st.markdown(f'<span class="good">✔</span> {esc(p)}', unsafe_allow_html=True)
    st.markdown(f'<div class="notice">{esc(risk["disclaimer"])}</div>', unsafe_allow_html=True)

# --- Headers ---
with tabs[1]:
    st.subheader("Extracted headers")
    st.dataframe(pd.DataFrame(parsed.metadata_rows(), columns=["Header", "Value"]), hide_index=True, width="stretch")
    st.subheader("Authentication-Results")
    st.dataframe(pd.DataFrame([{"Mechanism": auth[k].mechanism, "Status": auth[k].status, "Raw result": auth[k].raw_result or "-",
                                "Domain": auth[k].domain or "-", "Source": auth[k].source, "Detail": auth[k].detail or "-"}
                               for k in ("spf", "dkim", "dmarc")]), hide_index=True, width="stretch")
    for n in auth["notes"]:
        st.caption(n)
    with st.expander(f"Received headers ({len(parsed.received)}) - newest first, as stored in the file"):
        for i, r in enumerate(parsed.received, 1):
            st.code(r, language="text")
    if parsed.authentication_results:
        with st.expander("Raw Authentication-Results"):
            for r in parsed.authentication_results:
                st.code(r, language="text")
    if parsed.attachments:
        st.subheader("Attachments (listed only, never opened)")
        st.dataframe(pd.DataFrame(parsed.attachments), hide_index=True, width="stretch")
    with st.expander("Raw headers", expanded=False):
        st.code(parsed.raw_headers, language="text")

# --- IP investigation ---
with tabs[2]:
    st.subheader("Sender IP determination")
    st.markdown(f"**Result:** {esc(sender.headline)}")
    for r in sender.reasons:
        st.markdown(f"- **Why:** {r}")
    for c in sender.caveats:
        st.markdown(f"- ⚠️ {c}")
    st.info(sender.origin_statement)
    if sender.earlier_candidates:
        st.markdown("**Earlier external IPs in the chain (lower reliability)**")
        st.dataframe(pd.DataFrame(sender.earlier_candidates), hide_index=True, width="stretch")
    st.subheader("All IP addresses found")
    if result["ip_table"]:
        st.dataframe(pd.DataFrame(result["ip_table"]), hide_index=True, width="stretch")
    else:
        st.write("No IP addresses were found in the headers.")
    st.caption("Documentation-range addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are treated as external only so the "
               "synthetic samples can demonstrate the logic; in real mail they would be flagged as reserved.")
    st.subheader("IP intelligence (optional)")
    intel = result["intel"]
    if not use_intel:
        st.write("Not requested. Tick *IP intelligence* in the sidebar to query a configured provider.")
    elif intel is None:
        st.write("No sending IP to look up.")
    else:
        for m in intel["messages"]:
            st.warning(m)
        if intel["geolocation"]:
            st.markdown("**Geolocation / network (ipinfo.io)**")
            st.json({k: v for k, v in intel["geolocation"].items() if v})
        if intel["reputation"]:
            st.markdown("**Reputation (AbuseIPDB)**")
            st.json({k: v for k, v in intel["reputation"].items() if v is not None})
    st.markdown(f'<div class="notice">{esc(GEO_DISCLAIMER)}</div>', unsafe_allow_html=True)

# --- Routing ---
with tabs[3]:
    st.subheader("Email routing path (oldest hop → recipient)")
    if not hops:
        st.warning("No Received headers, so no routing path can be drawn.")
    else:
        xs = list(range(len(hops)))
        names = [f"{h.endpoint_label}<br>{h.from_ip or 'no IP'}" for h in hops]
        hover = [f"Hop {h.index}<br>from: {esc(h.from_text)}<br>by: {esc(h.by_host)}<br>time: {esc(h.timestamp_raw)}" for h in hops]
        # one extra node for the final receiving server
        xs.append(len(hops))
        names.append(f"{hops[-1].by_host or 'recipient server'}<br>(final recorded server)")
        hover.append("Server that wrote the newest Received header")
        fig = go.Figure()
        for i in range(1, len(hops)):
            ok = hops[i].link_ok
            bad = ok is False or hops[i].time_ok is False
            fig.add_trace(go.Scatter(x=[i - 1, i], y=[0, 0], mode="lines", hoverinfo="skip", showlegend=False,
                                     line=dict(color="#ff5c5c" if bad else "#36d1dc", width=3, dash="dash" if bad else "solid")))
        fig.add_trace(go.Scatter(
            x=xs, y=[0] * len(xs), mode="markers+text", text=names, textposition="top center", textfont=dict(size=12), hovertext=hover, hoverinfo="text",
            marker=dict(size=26, color=["#f5b942" if (i < len(hops) and hops[i].index == sender.hop_index) else "#36d1dc" for i in range(len(xs))],
                        line=dict(color="#0a1220", width=2)), showlegend=False))
        fig.update_layout(height=250, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={"color": "#e6edf6"},
                          xaxis=dict(visible=False, range=[-0.6, len(xs) - 0.4]), yaxis=dict(visible=False, range=[-0.6, 1.0]),
                          margin=dict(l=10, r=10, t=10, b=10))
        st.plotly_chart(fig, width="stretch")
        st.caption("Amber node: hop that recorded the most likely sending IP. Red dashed link: that hop's server names or timestamps do not connect to the previous hop.")
        rows = [{"Hop": h.index, "From (claimed)": h.helo or "-", "Reverse DNS": "none (unknown)" if h.rdns_unknown else (h.rdns or "-"),
                 "IP": h.from_ip or "-", "By": h.by_host or "-", "Protocol": h.protocol or "-", "Timestamp": h.timestamp_raw or "-",
                 "Delay (s)": str(int(h.delay_seconds)) if h.delay_seconds is not None else "-",
                 "Chain check": ("OK" if h.link_ok else h.link_note) if h.link_ok is not None else "n/a"} for h in hops]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
        st.caption("Received headers are added on top by each server, so the file lists newest first; this table is reversed into chronological order. "
                   "Hops written before a server you trust can be forged.")

# --- Indicators ---
with tabs[4]:
    st.subheader("Suspicious indicators")
    if not result["indicators"]:
        st.success("No indicators were triggered by this tool's rules. That does not guarantee the message is safe.")
    for ind in result["indicators"]:
        ev = f'<div class="ev">{esc(ind["evidence"])}</div>' if ind["evidence"] else ""
        st.markdown(f'<div class="indicator"><div class="t"><span class="sev sev-{ind["severity"]}">{ind["severity"].upper()}</span>'
                    f'{esc(ind["title"])} <span style="color:#8fa3bd;font-size:.75rem">+{ind["points"]}</span></div>'
                    f'<div class="e">{esc(ind["explanation"])}</div>{ev}</div>', unsafe_allow_html=True)

# --- Report ---
with tabs[5]:
    st.subheader("Download investigation report")
    st.write("A PDF with metadata, headers, IP analysis, SPF/DKIM/DMARC, indicators, risk assessment and summary.")
    try:
        pdf = generate_pdf_report(result)
        stem = Path(parsed.source_name).stem or "email"
        st.download_button("⬇️ Download PDF report", data=pdf, file_name=f"report_{stem}.pdf", mime="application/pdf")
    except Exception as exc:
        st.error(f"The PDF could not be generated ({type(exc).__name__}).")
    st.markdown(f'<div class="notice">{esc(risk["disclaimer"])}</div>', unsafe_allow_html=True)
