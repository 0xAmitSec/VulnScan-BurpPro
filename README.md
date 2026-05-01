# VulnScan — Advanced Web Vulnerability Scanner

```
 __   __      _       _____
 \ \ / /     | |     /  __|
  \ V / _   _| |_ __ \ `--.  ___ __ _ _ __
  /   \| | | | | '_ \ `--. \/ __/ _` | '_ \
 / /^\ \ |_| | | | | /\__/ / (_| (_| | | | |
 \/   \/\__,_|_|_| |_\____/ \___\__,_|_| |_|
    Aggressive Web Vulnerability Scanner v2.0
    Burp Suite Pro Edition  |  Ethical Use Only
```

> **Web App VAPT Tool | Burp Suite Pro Integration | Bug Bounty Ready | Python 3.10+**

Built by [0xAmitSec](https://github.com/0xAmitSec) — Senior Cybersecurity Consultant | CEHv12 | CCSP | Google VRP Awardee

---

## What is this?

`VulnScan` is an aggressive, async web vulnerability scanner with full **Burp Suite Pro REST API integration**. It combines automated vulnerability detection with Burp's active scanner — giving maximum coverage for bug bounty and authorized penetration testing engagements.

- **Automated scanning** — XSS, SQLi, SSRF, Sensitive Data, Info Disclosure
- **Burp Suite Pro integration** — Active scanner trigger, Collaborator OOB detection, Sitemap sync
- **Recon modules** — Subdomain enumeration, Port scanning, DNS analysis
- **HTML + JSON reports** — Client-ready output

---

## Stats

| Module | Coverage |
|---|---|
| Vulnerability Types | 5 (XSS, SQLi, SSRF, Sensitive Data, Info Disclosure) |
| Recon Modules | 3 (Subdomain, Port Scan, DNS) |
| Scan Profiles | 3 (Quick, Deep, API) |
| Report Formats | 2 (HTML, JSON) |
| Burp Integration | Full REST API + Collaborator OOB |

---

## Structure

```
vulnscan/
├── main.py                    # Entry point — CLI interface
├── requirements.txt           # Dependencies
├── core/
│   ├── engine.py              # Main scan engine
│   ├── config.py              # Scan configuration
│   └── logger.py              # Logging system
├── modules/
│   ├── vulns/
│   │   ├── xss/scanner.py     # XSS detection
│   │   ├── sqli/scanner.py    # SQL Injection detection
│   │   ├── ssrf/scanner.py    # SSRF detection
│   │   ├── sensitive_data/    # Sensitive data exposure
│   │   ├── info_disclosure/   # Information disclosure
│   │   └── multi_scanner.py   # Combined scanner
│   ├── web/
│   │   └── crawler.py         # Web crawler
│   └── recon/
│       ├── subdomain.py       # Subdomain enumeration
│       ├── port_scan.py       # Port scanning
│       └── dns.py             # DNS analysis
├── integrations/
│   ├── burp.py                # Burp Suite Pro REST API client
│   └── burp_extension.py      # Burp extension
├── reporting/
│   └── report.py              # HTML + JSON report generator
├── database/
│   └── models.py              # SQLite findings storage
├── utils/
│   ├── http_client.py         # Async HTTP client
│   └── scope_checker.py       # Scope validation
└── config/
    └── default.yaml           # Default configuration
```

---

## Vulnerability Modules

### Automated Detection

| Vulnerability | Module | Method |
|---|---|---|
| Cross-Site Scripting (XSS) | `modules/vulns/xss` | Reflected + Stored + DOM |
| SQL Injection | `modules/vulns/sqli` | Error-based + Blind + Time-based |
| SSRF | `modules/vulns/ssrf` | OOB via Burp Collaborator |
| Sensitive Data Exposure | `modules/vulns/sensitive_data` | Regex pattern matching |
| Information Disclosure | `modules/vulns/info_disclosure` | Header + Response analysis |

### Recon Modules

| Module | Capability |
|---|---|
| Subdomain Enumeration | Multi-source subdomain discovery |
| Port Scanning | Nmap-based service detection |
| DNS Analysis | DNS record enumeration + zone transfer |

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan (routes through Burp proxy)
python main.py -u https://target.com

# Deep scan with all modules
python main.py -u https://target.com --profile deep

# Full Burp Suite Pro integration
python main.py -u https://target.com \
  --burp-api http://127.0.0.1:1337 \
  --burp-key YOUR_API_KEY \
  --burp-collab abc123.burpcollaborator.net \
  --burp-scan --aggressive

# With custom auth headers
python main.py -u https://target.com \
  -H "Cookie: session=abc123" \
  -H "Authorization: Bearer TOKEN" \
  --aggressive
```

---

## Scan Profiles

| Profile | Description |
|---|---|
| `quick` | Fast scan — critical checks only |
| `deep` | Full scan — all modules, all payloads |
| `api` | API-focused — REST endpoint testing |
| `--aggressive` | Maximum mode — 50 threads, all modules, OOB detection |

---

## Burp Suite Pro Integration

```bash
# Step 1 — Enable REST API in Burp
# Burp → User Options → REST API → Enable → Copy API Key

# Step 2 — Run with Burp integration
python main.py -u https://target.com \
  --burp-api http://127.0.0.1:1337 \
  --burp-key YOUR_KEY \
  --burp-scan \
  --burp-sitemap

# Step 3 — OOB blind detection via Collaborator
python main.py -u https://target.com \
  --burp-collab YOUR.burpcollaborator.net \
  --aggressive
```

---

## Reports

VulnScan generates two report formats automatically:

- **HTML Report** — Visual, client-ready, color-coded by severity
- **JSON Report** — Machine-readable, integrates with JIRA / HackerOne / Bugcrowd

Reports saved to `output/reports/` directory.

---

## Authorization

> This tool is intended **only** for assets you own or have written authorization to assess — bug bounty in-scope assets, authorized penetration testing engagements.

Unauthorized use against systems you do not own is illegal. The author is not responsible for misuse.

---

## About

**Author:** [0xAmitSec](https://github.com/0xAmitSec) — Amit Shrivastav
**Role:** Senior Cybersecurity Consultant @ Capgemini | Ex IAF-CERT | Ministry of Defence
**Certifications:** CCSP (ISC2) | CEHv12 | MeitY Certified | AWS Security
**Recognition:** Google Vulnerability Reward Program — Rabbit & Dragon Award (2024)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/amit-shrivastava-cyber-security-auditor-146b6a248)

---

**License:** MIT — use freely, attribution appreciated.

> *"The best vulnerability scanner is the one that finds what others miss."*
