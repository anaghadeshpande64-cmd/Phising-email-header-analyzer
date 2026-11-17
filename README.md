# Phishing Email Header Analyzer
**Email Forensics and Sender IP Investigation Tool**

An educational, beginner-friendly cybersecurity project that parses email headers, examines the
`Received` chain, reads SPF / DKIM / DMARC results, flags phishing indicators and produces a
rule-based risk assessment with a downloadable PDF report. Built with Python and Streamlit.

> **Important:** this is an *investigative aid*, not a definitive phishing detector. It inspects headers only.
> It does not open links, scan message bodies or open attachments.

---

## 1. Problem statement
Phishing is the most common way attackers gain a foothold. The visible parts of an email (display name,
subject) are trivial to fake, but the **headers** record how the message travelled and how receiving servers
judged it. Reading them by hand is slow and error-prone, especially for beginners.

## 2. Objectives
- Extract and display the key headers of a suspicious email.
- Reconstruct the routing path in chronological order and find the most defensible external sending IP,
  **without** assuming the first IP is the sender.
- Report SPF, DKIM and DMARC outcomes honestly (a missing header is `UNKNOWN`, never `PASS`).
- Detect common phishing indicators and explain each one.
- Provide a transparent risk score and a PDF report.
- Run fully offline on the bundled sample dataset.

## 3. Technologies
| Purpose | Technology |
|---|---|
| Language | Python 3.10+ |
| Dashboard | Streamlit |
| Parsing | `email`, `email.parser` (standard library) |
| IP utilities | `ipaddress`, `socket` (standard library) |
| Optional IP intelligence | `requests` (ipinfo.io, AbuseIPDB) |
| Tables / charts | Pandas, Plotly |
| PDF report | ReportLab |
| Tests | pytest |

## 4. System architecture
```
 .eml upload / pasted headers / sample
              |
        email_parser.py     safe parsing, size limit, attachments only listed
              |
   +----------+-----------+------------------+
   |                      |                  |
ip_analyzer.py   authentication_checker.py   (optional) IP intelligence
 hops, IPs,        SPF / DKIM / DMARC        ipinfo.io / AbuseIPDB
 sender choice     from Authentication-Results   (IP address only is sent)
   |                      |
   +----------+-----------+
              |
     phishing_detector.py   indicators with severity + explanation
              |
     risk_assessment.py     additive score -> LOW / MEDIUM / HIGH
              |
   app.py (dashboard)   +   report_generator.py (PDF)
```
`modules/pipeline.py` wires the steps together; `modules/domain_utils.py` holds small shared helpers.

## 5. Project structure
```
phishing-email-header-analyzer/
    app.py                      Streamlit dashboard
    requirements.txt
    README.md
    .env.example                template for optional API keys
    .gitignore
    .streamlit/config.toml      dark theme
    modules/
        email_parser.py         header extraction
        ip_analyzer.py          IPs, Received chain, sender identification, optional intelligence
        authentication_checker.py
        phishing_detector.py
        risk_assessment.py
        report_generator.py
        pipeline.py             runs the whole analysis
        domain_utils.py         domain / look-alike helpers
    samples/
        legitimate_email.eml    all authentication passes
        phishing_email.eml      failed authentication, look-alike domain, forged chain
        suspicious_email.eml    incomplete authentication headers
    assets/style.css
    reports/                    saved PDFs (optional)
    tests/                      pytest suite
```

## 6. Installation (Windows PowerShell + VS Code)
1. Install **Python 3.10 or newer** from python.org (tick *Add python.exe to PATH*).
2. Extract the ZIP, then open the extracted `phishing-email-header-analyzer` folder in VS Code
   (*File → Open Folder*). Open a terminal with **Ctrl + `**.
3. Create and activate a virtual environment:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
   If PowerShell blocks the script, run once: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
4. Install dependencies:
```powershell
pip install -r requirements.txt
```
5. *(Optional)* enable IP intelligence:
```powershell
Copy-Item .env.example .env
notepad .env
```
   Paste your own keys after `IPINFO_TOKEN=` and/or `ABUSEIPDB_API_KEY=`. Never share or commit `.env`.

## 7. Running the application
```powershell
streamlit run app.py
```
The browser opens at `http://localhost:8501`. Run the tests with:
```powershell
python -m pytest -q
```

## 8. Analysing an email
1. **Sample email** (default): choose one of the three synthetic samples. Works offline.
2. **Upload .eml file**: in Gmail open the message → ⋮ → *Download message*; in Outlook choose *Save As* → `.eml`.
3. **Paste raw headers**: in Gmail → ⋮ → *Show original*; in Outlook → *File → Properties → Internet headers*.
4. Review the tabs: **Overview**, **Headers**, **IP investigation**, **Routing path**, **Indicators**, **Report**.
5. Download the PDF from the **Report** tab.

Never open attachments or click links in a suspicious email in order to "check" it.

## 9. SPF, DKIM and DMARC
- **SPF (Sender Policy Framework)**: the domain publishes in DNS which servers may send mail for it. The receiver checks whether
  the connecting IP is on that list for the *envelope sender* (Return-Path / `smtp.mailfrom`).
- **DKIM (DomainKeys Identified Mail)**: the sending server signs selected headers and the body with a private key. The receiver
  verifies the signature with a public key in DNS (`selector._domainkey.domain`). A valid signature shows the message was not
  altered and that the signing domain (`d=`) authorised it.
- **DMARC**: ties both to the visible **From** domain. Mail passes only if SPF *or* DKIM passes **and is aligned** with the From
  domain. The domain owner's policy (`none`, `quarantine`, `reject`) tells receivers what to do on failure.

Results are shown as **PASS / FAIL / NONE / UNKNOWN**. `softfail` is mapped to FAIL, `neutral` to NONE, and errors or missing data to
UNKNOWN. This tool **reads** the verdicts that the receiving server recorded in `Authentication-Results` (and `Received-SPF` for SPF);
it does **not** repeat the DNS checks or verify signatures itself. If several `Authentication-Results` headers exist, only the topmost
(newest) is used because senders can forge extra ones.

## 10. How `Received` headers work
Every mail server that handles a message adds a `Received:` line **at the top**. Reading from the bottom up therefore gives the journey
in chronological order. A line typically records *from* (the server's claimed name, its reverse-DNS name and IP), *by* (the server that wrote
the line), *with* (protocol) and a timestamp. The tool checks that each hop's *from* matches the previous hop's *by* and that timestamps move
forward, and flags chains that do not connect.

## 11. IP tracing and its limits
- IPs are classified as public, private, loopback, link-local, shared (CGNAT), documentation or reserved.
- The tool selects the **newest hop that records an external connecting IP**, because that line was written by infrastructure closer to
  the recipient and is harder for an attacker to fake. It reports a confidence level (never "verified") with reasons and caveats.
- **Observed ≠ verified.** Headers written before the message reached a server you trust can be forged completely.
- The IP is often a mail server, relay, VPN or compromised host, not the author's device. Webmail providers usually hide the user's IP.
- **Geolocation is approximate** and shows where an address is registered or routed. It never identifies a person.
- If no reliable external IP exists, the tool says the origin **cannot be reliably determined**.
- The bundled samples use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The tool treats them as external
  candidates only so the demo works; real mail never carries them.

## 12. Risk assessment
Each indicator carries points; the score is their sum (max 100): **0–24 LOW**, **25–54 MEDIUM**, **55+ HIGH**. Indicators include failed
SPF/DKIM/DMARC, missing authentication data, From/Reply-To mismatch, Return-Path mismatch, look-alike or impersonating domains, display-name
spoofing, broken or time-inconsistent `Received` chains, missing reverse DNS, risky attachment types and (when configured) poor IP reputation.
The result is an assessment to guide investigation. Legitimate mail can score above zero and well-crafted phishing can score zero.

## 13. Privacy and security
- Uploaded emails are **never** sent to third-party services. Optional lookups send **only a public IP address**, and only if you tick the box and
  configured a key. Reverse DNS (also opt-in) uses your system's DNS resolver.
- Input is untrusted: size limit (10 MB), binary files rejected, attachments listed but never decoded or executed, all text HTML-escaped in the UI
  and escaped in the PDF.
- API keys come from environment variables / a local `.env` file and are never in source code.

## 14. Screenshots
Run the app, choose the *Phishing email* sample, and capture each tab (Windows: **Win + Shift + S**). Save them in a `screenshots/` folder:
`overview.png`, `routing.png`, `indicators.png`, `report.png`, then reference them here:
```markdown
![Overview](screenshots/overview.png)
```

## 15. Known limitations
- Header analysis only: no URL, body, attachment or image inspection.
- Brand-impersonation checks use a small built-in brand list and simple edit-distance/look-alike rules; they will miss many cases and can give false positives.
- Registered-domain detection is a heuristic (no Public Suffix List).
- Parsing covers common `Received` formats; unusual formats degrade to "no hostname data" rather than guesses.
- IP intelligence needs your own free API keys and internet access. It was not exercised in the automated tests (no keys or network were used).

## 16. Future enhancements
- Live DNS verification of SPF, DKIM and DMARC records.
- URL extraction with safe, offline reputation checks.
- Batch analysis of folders / mbox files.
- Custom protected-brand list in the UI.
- ARC header support, `.msg` import, and export to JSON / STIX.
- Interactive map of hop geolocation (when intelligence is configured).

## 17. License / disclaimer
Educational use. Sample data is synthetic: fictional domains and reserved example IP ranges. Not affiliated with any email provider.
#   P h i s i n g - e m a i l - h e a d e r - a n a l y z e r  
 