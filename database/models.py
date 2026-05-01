"""
VulnScan - Finding Data Model
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_CVSS = {
    "Critical": (9.0, 10.0),
    "High":     (7.0, 8.9),
    "Medium":   (4.0, 6.9),
    "Low":      (0.1, 3.9),
    "Info":     (0.0, 0.0),
}

CWE_MAP = {
    "XSS":                "CWE-79",
    "Reflected XSS":      "CWE-79",
    "Stored XSS":         "CWE-79",
    "DOM XSS":            "CWE-79",
    "SQL Injection":      "CWE-89",
    "SQLi":               "CWE-89",
    "SSRF":               "CWE-918",
    "SSTI":               "CWE-94",
    "XXE":                "CWE-611",
    "LFI":                "CWE-22",
    "RFI":                "CWE-98",
    "Path Traversal":     "CWE-22",
    "Open Redirect":      "CWE-601",
    "Command Injection":  "CWE-78",
    "IDOR":               "CWE-639",
    "CORS":               "CWE-942",
    "Clickjacking":       "CWE-1021",
    "Info Disclosure":    "CWE-200",
    "Git Exposed":        "CWE-538",
    "Env Exposed":        "CWE-312",
    "Backup File":        "CWE-538",
    "Directory Listing":  "CWE-548",
    "Subdomain Takeover": "CWE-284",
    "Default Credentials":"CWE-1392",
    "JWT Weakness":       "CWE-347",
    "Deserialization":    "CWE-502",
    "CSRF":               "CWE-352",
    "Request Smuggling":  "CWE-444",
    "Cache Poisoning":    "CWE-444",
}

REMEDIATION_MAP = {
    "XSS":                "Implement output encoding, use Content Security Policy (CSP), validate all user input",
    "Reflected XSS":      "Encode output in HTML context, use CSP headers, validate and sanitize all input",
    "Stored XSS":         "Sanitize stored data, encode on output, implement strict CSP policy",
    "SQL Injection":      "Use parameterized queries / prepared statements, implement WAF, apply least privilege DB permissions",
    "SSRF":               "Validate and whitelist URLs, block internal IP ranges, use allowlist for allowed protocols",
    "SSTI":               "Use sandboxed template engines, avoid rendering user-controlled data in templates",
    "XXE":                "Disable external entity processing in XML parser, use JSON instead of XML where possible",
    "LFI":                "Validate file path input, use whitelist of allowed files, chroot sandbox",
    "Open Redirect":      "Use allowlist for redirect URLs, avoid user-controlled redirect parameters",
    "Command Injection":  "Never pass user input to system commands, use safe APIs, whitelist allowed commands",
    "IDOR":               "Implement proper authorization checks, use indirect object references, validate ownership",
    "CORS":               "Set specific allowed origins, avoid wildcard with credentials, validate Origin header server-side",
    "Info Disclosure":    "Remove sensitive files from web root, configure server to return proper error pages",
    "Git Exposed":        "Add .git to webserver deny rules, use git-dumper to verify exposure, rotate all exposed credentials",
    "Env Exposed":        "Move .env outside web root, add to .htaccess deny rules, rotate all exposed secrets immediately",
    "Directory Listing":  "Disable directory browsing in web server config (Options -Indexes for Apache)",
    "Subdomain Takeover": "Remove dangling CNAME records, claim the resource or delete the DNS entry",
    "Default Credentials":"Change all default credentials, implement credential rotation policy",
    "JWT Weakness":       "Use strong secrets (256+ bits), validate algorithm explicitly, implement token expiry",
    "Deserialization":    "Avoid deserializing untrusted data, use integrity checks, update serialization libraries",
    "Request Smuggling":  "Ensure consistent CL and TE header handling, normalize requests at reverse proxy",
    "Security Headers":   "Add X-Frame-Options, X-Content-Type-Options, HSTS, CSP, Referrer-Policy headers",
}


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    vuln_type: str = ""
    severity: str = "Info"
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response_snippet: str = ""
    cwe: str = ""
    cvss_score: float = 0.0
    remediation: str = ""
    description: str = ""
    tool: str = "VulnScan"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    confirmed: bool = False
    false_positive: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.cwe and self.vuln_type in CWE_MAP:
            self.cwe = CWE_MAP[self.vuln_type]
        if not self.remediation and self.vuln_type in REMEDIATION_MAP:
            self.remediation = REMEDIATION_MAP[self.vuln_type]
        if self.cvss_score == 0.0:
            rng = SEVERITY_CVSS.get(self.severity, (0.0, 0.0))
            self.cvss_score = round((rng[0] + rng[1]) / 2, 1)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "request": self.request,
            "response_snippet": self.response_snippet,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "description": self.description,
            "tool": self.tool,
            "timestamp": self.timestamp,
            "confirmed": self.confirmed,
            "false_positive": self.false_positive,
        }

    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)
