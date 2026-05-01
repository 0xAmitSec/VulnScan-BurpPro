# VulnScan — Advanced Web Vulnerability Scanner

Bug Bounty & Penetration Testing Tool | Python 3.10+ | Async

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan
python main.py -u https://target.com

# Quick scan (faster, fewer checks)
python main.py -u https://target.com --profile quick

# Full deep scan with proxy (Burp Suite)
python main.py -u https://target.com --proxy http://127.0.0.1:8080

# Scan with custom scope
python main.py -u https://target.com -s target.com -s api.target.com

# API-only scan
python main.py -u https://api.target.com --profile api

# With custom headers (auth token)
python main.py -u https://target.com -H "Authorization: Bearer TOKEN"

# Using config file
python main.py -u https://target.com --config config/default.yaml
```

## What It Does

### Phase 1: Reconnaissance
- Subdomain enumeration (crt.sh, HackerTarget, DNS brute force, Wayback)
- DNS records (A, MX, NS, TXT, SOA, zone transfer)
- Port scanning (100+ common ports)
- Dangerous service detection

### Phase 2: Web Crawling
- JS-aware crawler with form extraction
- JavaScript analysis — API endpoints, hardcoded secrets
- Parameter discovery

### Phase 3: Vulnerability Scanning
- XSS (Reflected, Stored pattern, DOM)
- SQL Injection (Error, Boolean-blind, Time-based, UNION)
- SSRF (Cloud metadata, Blind, Header injection)
- SSTI (Jinja2, Twig, Freemarker detection)
- LFI / Path Traversal
- Open Redirect
- Information Disclosure (.git, .env, backup files)
- CORS Misconfiguration
- Security Headers
- Clickjacking
- Dangerous HTTP Methods
- Directory Listing

### Phase 4: Reporting
- Professional HTML report with filter
- JSON report for programmatic use
- CVSS scores and CWE IDs
- Remediation suggestions

## Output Structure

```
output/
├── reports/
│   ├── vulnscan_report_20250101_120000.html
│   └── vulnscan_report_20250101_120000.json
└── logs/
    └── scan_20250101_120000.log
```

## Ethical Use

This tool is for **authorized security testing only**.
- Only test targets you own or have written permission to test
- Stay within the defined scope of bug bounty programs
- Never cause damage or access production data
- Follow responsible disclosure guidelines
