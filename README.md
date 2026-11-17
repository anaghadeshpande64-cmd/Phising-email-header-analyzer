# 🛡️ Phishing Email Header Analyzer

**Email Forensics and Sender IP Investigation Tool**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ff4b4b)
![Tests](https://img.shields.io/badge/tests-41%20passing-brightgreen)
![License](https://img.shields.io/badge/use-educational-lightgrey)

An educational, beginner-friendly cybersecurity project that parses email headers, reconstructs the `Received` routing path, reads SPF / DKIM / DMARC results, flags phishing indicators, and produces a rule-based risk assessment with a downloadable PDF report.

> **Important:** this is an *investigative aid*, not a definitive phishing detector. It inspects headers only. It does not open links, scan message bodies or open attachments.

---

## ✨ Features

- Upload an `.eml` file, paste raw headers, or use the 3 built-in sample emails (works fully offline)
- Extracts From, To, Reply-To, Return-Path, Subject, Date, Message-ID, Received, Authentication-Results, X-Originating-IP
- `Received` chain analysed in chronological order, with checks for broken links and out-of-order timestamps
- IP classification: public, private, loopback, link-local, CGNAT, documentation, reserved
- Most likely external sending IP with a confidence level and reasons, and a clear statement when the origin **cannot** be determined
- SPF / DKIM / DMARC shown as **PASS / FAIL / NONE / UNKNOWN** (a missing header is never reported as PASS)
- Phishing indicators with explanations: From/Reply-To mismatch, look-alike domains, display-name spoofing, failed authentication, forged-looking routing, risky attachments and more
- Transparent additive risk score: **LOW / MEDIUM / HIGH**
- Dark cybersecurity dashboard with risk gauge, status cards and routing-path visualisation
- Detailed **PDF report** download
- Optional IP intelligence (geolocation, ASN, reputation) via your own API keys. Only the IP address is ever sent.

## 📖 Problem statement

Phishing is one of the most common ways attackers gain access to accounts and networks. The visible parts of an email (display name, subject) are easy to fake, but the **headers** record how the message travelled and how receiving servers judged it. Reading them by hand is slow and error-prone, especially for beginners.

## 🎯 Objectives

- Extract and display the key headers of a suspicious email.
- Rebuild the routing path and find the most defensible external sending IP **without** assuming the first IP is the sender.
- Report SPF, DKIM and DMARC outcomes honestly.
- Detect common phishing indicators and explain each one.
- Provide a transparent risk score and a PDF report.
- Run fully offline on the bundled sample dataset.

## 🧰 Technologies

| Purpose | Technology |
|---|---|
| Language | Python 3.10+ |
| Dashboard | Streamlit |
| Parsing | `email`, `email.parser` (standard library) |
| IP utilities | `ipaddress`, `socket` (standard library) |
| Optional IP intelligence | `requests` (ipinfo.io, AbuseIPDB) |
| Tables and charts | Pandas, Plotly |
| PDF report | ReportLab |
| Tests | pytest |

## 🏗️ System architecture

```text
 .eml upload / pasted headers / sample
              |
        email_parser.py          safe parsing, size limit, attachments only listed
              |
   +----------+-----------+------------------+
   |                      |                  |
ip_analyzer.py   authentication_checker.py   (optional) IP intelligence
 hops, IPs,        SPF / DKIM / DMARC        ipinfo.io / AbuseIPDB
 sender choice     from Authentication-Results   (IP address only is sent)
   |                      |
   +----------+-----------+
              |
     phishing_detector.py        indicators with severity + explanation
              |
     risk_assessment.py          additive score -> LOW / MEDIUM / HIGH
              |
   app.py (dashboard)   +   report_generator.py (PDF)
```

`modules/pipeline.py` wires the steps together and `modules/domain_utils.py` holds small shared helpers.

## 📁 Project structure

```text
phishing-email-header-analyzer/
├── app.py                        Streamlit dashboard
├── requirements.txt
├── README.md
├── .env.example                  template for optional API keys
├── .gitignore
├── .streamlit/config.toml        dark theme
├── modules/
│   ├── email_parser.py           header extraction
│   ├── ip_analyzer.py            IPs, Received chain, sender identification, optional intelligence
│   ├── authentication_checker.py SPF / DKIM / DMARC
│   ├── phishing_detector.py      indicator rules
│   ├── risk_assessment.py        scoring
│   ├── report_generator.py       PDF report
│   ├── pipeline.py               runs the whole analysis
│   └── domain_utils.py           domain / look-alike helpers
├── samples/
│   ├── legitimate_email.eml      all authentication passes
│   ├── phishing_email.eml        failed authentication, look-alike domain, forged chain
│   └── suspicious_email.eml      incomplete authentication headers
├── assets/style.css
├── reports/                      saved PDFs (optional)
└── tests/                        pytest suite (41 tests)
```

## ✅ Prerequisites

- **Python 3.10 or newer** (tested on 3.13). Download from [python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"** during installation.
- **VS Code** (optional) with the Python extension.
- Internet access **once** to install packages. No paid API keys and no email account are needed.

Check your setup:

```powershell
python --version
python -m pip --version
```

## 🚀 Installation (Windows PowerShell)

Open the project folder in VS Code (or `cd` into it), then run:

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
python -m pip install -r requirements.txt
```

If PowerShell blocks the activation script, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## ▶️ Running the application

```powershell
python -m streamlit run app.py
```

The app opens at **http://localhost:8501**.

> On the very first run Streamlit may ask for an email address for its newsletter. This is unrelated to this project. Leave it blank and press **Enter**.

Run the automated tests:

```powershell
python -m pytest -q
```

Expected result: `41 passed`.

## 🔍 How to upload and analyze an email

1. **Sample email** (default): pick one of the three synthetic samples in the sidebar. Works offline.
2. **Upload .eml file**: in Gmail open the message → ⋮ → *Download message*. In Outlook use *Save As* → `.eml`.
3. **Paste raw headers**: in Gmail → ⋮ → *Show original*. In Outlook → *File → Properties → Internet headers*.
4. Review the tabs: **Overview**, **Headers**, **IP investigation**, **Routing path**, **Indicators**, **Report**.
5. Download the PDF from the **Report** tab.

Never open attachments or click links in a suspicious email in order to "check" it.

### Expected results for the samples

| Sample | Risk | SPF / DKIM / DMARC | Main findings |
|---|---|---|---|
| Legitimate | LOW (0) | PASS / PASS / PASS | None |
| Suspicious | MEDIUM (36) | NONE / UNKNOWN / UNKNOWN | From and Reply-To differ, incomplete authentication |
| Phishing | HIGH (100) | FAIL / FAIL / FAIL | Look-alike domain, Received chain does not connect, timestamps out of order |

## 🔐 SPF, DKIM and DMARC explained

- **SPF (Sender Policy Framework):** the domain publishes in DNS which servers may send mail for it. The receiver checks whether the connecting IP is on that list for the *envelope sender* (Return-Path / `smtp.mailfrom`).
- **DKIM (DomainKeys Identified Mail):** the sending server signs selected headers and the body with a private key. The receiver verifies the signature with a public key in DNS (`selector._domainkey.domain`). A valid signature shows the message was not altered and that the signing domain (`d=`) authorised it.
- **DMARC:** ties both to the visible **From** domain. Mail passes only if SPF *or* DKIM passes **and is aligned** with the From domain. The domain owner's policy (`none`, `quarantine`, `reject`) tells receivers what to do on failure.

Results are shown as **PASS / FAIL / NONE / UNKNOWN**. `softfail` maps to FAIL, `neutral` to NONE, and errors or missing data to UNKNOWN.

> This tool **reads** the verdicts that the receiving server recorded in `Authentication-Results` (and `Received-SPF` for SPF). It does **not** repeat the DNS checks or verify signatures itself. If several `Authentication-Results` headers exist, only the topmost (newest) is used, because senders can forge extra ones.

## 📬 How `Received` headers work

Every mail server that handles a message adds a `Received:` line **at the top**. Reading from the bottom up gives the journey in chronological order. A line typically records:

- **from**: the server's claimed name, its reverse-DNS name and its IP
- **by**: the server that wrote the line
- **with**: the protocol used
- a **timestamp**

The tool checks that each hop's *from* matches the previous hop's *by* and that timestamps move forward, and it flags chains that do not connect.

## 🌍 IP tracing and its limitations

- IPs are classified as public, private, loopback, link-local, shared (CGNAT), documentation or reserved.
- The tool selects the **newest hop that records an external connecting IP**, because that line was written by infrastructure closer to the recipient and is harder for an attacker to fake. It reports a confidence level (never "verified") with reasons and caveats.
- **Observed ≠ verified.** Headers written before the message reached a server you trust can be forged completely.
- The IP is often a mail server, relay, VPN or compromised host, not the author's device. Webmail providers usually hide the user's IP.
- **Geolocation is approximate.** It shows where an address is registered or routed and never identifies a person.
- If no reliable external IP exists, the tool says the origin **cannot be reliably determined**.
- The bundled samples use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). The tool treats them as external candidates only so the demo works. Real mail never carries them.

## 📊 Risk assessment

Each indicator carries points. The score is their sum (maximum 100):

| Score | Level |
|---|---|
| 0 – 24 | LOW RISK |
| 25 – 54 | MEDIUM RISK |
| 55 – 100 | HIGH RISK |

Indicators include failed SPF/DKIM/DMARC, missing authentication data, From/Reply-To mismatch, Return-Path mismatch, look-alike or impersonating domains, display-name spoofing, broken or time-inconsistent `Received` chains, missing reverse DNS, risky attachment types and (when configured) poor IP reputation.

The result guides an investigation. Legitimate mail can score above zero, and well-crafted phishing can score zero.

## 🌐 Optional: IP intelligence

The app works without any keys. To enable geolocation / ASN / reputation lookups with your own free keys:

```powershell
Copy-Item .env.example .env
notepad .env
```

```text
IPINFO_TOKEN=your_token_here
ABUSEIPDB_API_KEY=your_key_here
```

Then tick **IP intelligence** in the sidebar. Without keys the app says no data was retrieved and shows nothing invented. Never commit your `.env` file (it is already in `.gitignore`).

## 🔒 Privacy and security

- Uploaded emails are **never** sent to third-party services. Optional lookups send **only a public IP address**, and only if you tick the box and have configured a key. Reverse DNS (also opt-in) uses your system's DNS resolver.
- Input is treated as untrusted: 10 MB size limit, binary files rejected, attachments listed but never decoded or executed, all text HTML-escaped in the UI and escaped in the PDF.
- API keys are read from environment variables or a local `.env` file and are never in source code.

## 🖼️ Screenshots

Run the app, choose the *Phishing email* sample and capture each tab (Windows: **Win + Shift + S**). Save them in a `screenshots/` folder and reference them here:

```markdown
![Overview](screenshots/overview.png)
![Routing path](screenshots/routing.png)
![Indicators](screenshots/indicators.png)
```

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `pip` gives *Fatal error in launcher* | Use `python -m pip ...` instead of `pip ...` |
| `streamlit` is not recognised | Activate the virtual environment, or use `python -m streamlit run app.py` |
| PowerShell: *running scripts is disabled* | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `pip install` fails to build a package | Your Python may be too new. Install Python 3.12 or 3.13 and recreate the venv: `py -3.13 -m venv .venv` |
| Port 8501 already in use | `python -m streamlit run app.py --server.port 8502` |
| VS Code uses the wrong Python | Ctrl+Shift+P → *Python: Select Interpreter* → choose the `.venv` one |

## ⚠️ Known limitations

- Header analysis only: no URL, body, attachment or image inspection.
- Brand-impersonation checks use a small built-in brand list and simple look-alike / edit-distance rules. They will miss many cases and can give false positives.
- Registered-domain detection is a heuristic (no Public Suffix List).
- Parsing covers common `Received` formats. Unusual formats degrade to "no hostname data" rather than guesses.
- IP intelligence needs your own API keys and internet access. It was not covered by the automated tests.

## 🔮 Future enhancements

- Live DNS verification of SPF, DKIM and DMARC records
- URL extraction with safe, offline reputation checks
- Batch analysis of folders and mbox files
- Custom protected-brand list in the UI
- ARC header support, `.msg` import, and export to JSON / STIX
- Interactive map of hop geolocation when intelligence is configured

## 📄 License and disclaimer

For educational use. Sample data is synthetic: fictional domains and reserved example IP ranges. Not affiliated with any email provider. Results are investigative assessments, not proof of phishing or of legitimacy.
