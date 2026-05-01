"""
VulnScan - Sensitive Data Exposure Scanner
Detects: PII, Payment Card Data, Medical Data, Identity Documents,
         API Keys, Credentials, Indian-specific data (Aadhaar, PAN, UPI)
"""
import re
import asyncio
import json
from typing import List, Dict, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from database.models import Finding


# ══════════════════════════════════════════════════════════════
# REGEX PATTERNS — All sensitive data patterns
# ══════════════════════════════════════════════════════════════

PATTERNS = {

    # ── PAYMENT / ATM DATA ─────────────────────────────────────
    "Credit Card (Visa)": {
        "regex": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        "severity": "Critical",
        "category": "Payment",
        "description": "Visa credit/debit card number exposed",
        "validate": "luhn",
    },
    "Credit Card (Mastercard)": {
        "regex": r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
        "severity": "Critical",
        "category": "Payment",
        "description": "Mastercard number exposed",
        "validate": "luhn",
    },
    "Credit Card (Amex)": {
        "regex": r"\b3[47][0-9]{13}\b",
        "severity": "Critical",
        "category": "Payment",
        "description": "American Express card number exposed",
        "validate": "luhn",
    },
    "Credit Card (RuPay/Generic)": {
        "regex": r"\b(?:60|65|81|82)[0-9]{14}\b",
        "severity": "Critical",
        "category": "Payment",
        "description": "RuPay/generic card number exposed",
        "validate": "luhn",
    },
    "CVV Code": {
        "regex": r'["\']?cvv["\']?\s*[:=]\s*["\']?([0-9]{3,4})["\']?',
        "severity": "Critical",
        "category": "Payment",
        "description": "CVV/CVC security code exposed in response",
    },
    "Card Expiry": {
        "regex": r'["\']?exp(?:iry|_date|iration)?["\']?\s*[:=]\s*["\']?(\d{2}[\/\-]\d{2,4})["\']?',
        "severity": "Critical",
        "category": "Payment",
        "description": "Card expiry date exposed",
    },
    "Bank Account Number": {
        "regex": r'\b[0-9]{9,18}\b(?=.*(?:account|acc_no|account_number|bank))',
        "severity": "Critical",
        "category": "Payment",
        "description": "Bank account number in response",
    },
    "IFSC Code": {
        "regex": r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
        "severity": "High",
        "category": "Payment",
        "description": "IFSC code exposed — reveals bank branch",
    },
    "UPI ID": {
        "regex": r'\b[a-zA-Z0-9._-]+@(?:oksbi|okaxis|okicici|okhdfcbank|paytm|ybl|ibl|axl|upi|apl|abfspay|waicici|jupiteraxis)\b',
        "severity": "High",
        "category": "Payment",
        "description": "UPI ID exposed in response",
    },
    "PIN Number": {
        "regex": r'["\']?(?:pin|atm_pin|card_pin)["\']?\s*[:=]\s*["\']?([0-9]{4,6})["\']?',
        "severity": "Critical",
        "category": "Payment",
        "description": "ATM/card PIN exposed in response — Critical",
    },
    "SWIFT/BIC Code": {
        "regex": r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
        "severity": "Medium",
        "category": "Payment",
        "description": "SWIFT/BIC banking code exposed",
    },

    # ── IDENTITY DOCUMENTS ─────────────────────────────────────
    "Aadhaar Number": {
        "regex": r'\b[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',
        "severity": "Critical",
        "category": "Identity",
        "description": "Aadhaar number exposed — Indian national ID",
    },
    "PAN Card": {
        "regex": r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
        "severity": "Critical",
        "category": "Identity",
        "description": "PAN card number exposed — Indian tax ID",
    },
    "Passport Number (India)": {
        "regex": r'\b[A-PR-WY][1-9][0-9]{5}[0-9A-Z]\b',
        "severity": "Critical",
        "category": "Identity",
        "description": "Indian passport number exposed",
    },
    "Voter ID (India)": {
        "regex": r'\b[A-Z]{3}[0-9]{7}\b',
        "severity": "High",
        "category": "Identity",
        "description": "Indian Voter ID (EPIC) number exposed",
    },
    "Driving License (India)": {
        "regex": r'\b[A-Z]{2}[0-9]{2}[\s\-]?[0-9]{11}\b',
        "severity": "High",
        "category": "Identity",
        "description": "Indian driving license number exposed",
    },
    "SSN (US)": {
        "regex": r'\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b',
        "severity": "Critical",
        "category": "Identity",
        "description": "US Social Security Number exposed",
    },
    "National ID Pattern": {
        "regex": r'["\']?(?:national_id|nid|id_number|identity_number|id_no)["\']?\s*[:=]\s*["\']?([A-Z0-9]{6,20})["\']?',
        "severity": "Critical",
        "category": "Identity",
        "description": "National identity number in API response",
    },
    "Date of Birth": {
        "regex": r'["\']?(?:dob|date_of_birth|birth_date|birthdate)["\']?\s*[:=]\s*["\']?(\d{2}[\/\-]\d{2}[\/\-]\d{2,4})["\']?',
        "severity": "High",
        "category": "PII",
        "description": "Date of birth exposed in response",
    },

    # ── PII (Personal Identifiable Information) ────────────────
    "Email Address": {
        "regex": r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        "severity": "Medium",
        "category": "PII",
        "description": "Email address exposed in response",
        "min_count": 5,  # Only flag if 5+ emails found (likely data leak)
    },
    "Phone Number (India)": {
        "regex": r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b',
        "severity": "High",
        "category": "PII",
        "description": "Indian mobile phone number exposed",
        "min_count": 3,
    },
    "Phone Number (International)": {
        "regex": r'\+[1-9]\d{1,14}\b',
        "severity": "Medium",
        "category": "PII",
        "description": "International phone number exposed",
        "min_count": 3,
    },
    "Full Name Pattern": {
        "regex": r'["\']?(?:full_name|fullname|first_name|last_name|customer_name)["\']?\s*[:=]\s*["\']([A-Za-z\s]{3,50})["\']',
        "severity": "Medium",
        "category": "PII",
        "description": "Personal name fields exposed in API response",
    },
    "Home Address": {
        "regex": r'["\']?(?:address|home_address|street_address|billing_address|shipping_address)["\']?\s*[:=]\s*["\']([^"\']{10,100})["\']',
        "severity": "High",
        "category": "PII",
        "description": "Physical address exposed in API response",
    },
    "GPS Coordinates": {
        "regex": r'["\']?(?:lat|latitude)["\']?\s*[:=]\s*["\']?(-?\d{1,3}\.\d{4,})["\']?',
        "severity": "Medium",
        "category": "PII",
        "description": "GPS location coordinates in response",
    },
    "IP Address (Private)": {
        "regex": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "severity": "Low",
        "category": "PII",
        "description": "Internal IP address leaked in response",
    },

    # ── MEDICAL DATA (HIPAA) ───────────────────────────────────
    "Medical Record Number": {
        "regex": r'["\']?(?:mrn|medical_record|patient_id|patient_no|record_number)["\']?\s*[:=]\s*["\']?([A-Z0-9\-]{4,20})["\']?',
        "severity": "Critical",
        "category": "Medical",
        "description": "Medical Record Number (MRN) exposed — HIPAA violation",
    },
    "Diagnosis/ICD Code": {
        "regex": r'\b[A-Z][0-9]{2}\.?[0-9A-Z]{0,4}\b(?=.*(?:diagnosis|icd|condition|disease|disorder))',
        "severity": "Critical",
        "category": "Medical",
        "description": "ICD diagnosis code in response — medical condition exposed",
    },
    "Prescription Data": {
        "regex": r'["\']?(?:prescription|rx_number|drug_name|medication|dosage)["\']?\s*[:=]\s*["\']([^"\']{3,100})["\']',
        "severity": "Critical",
        "category": "Medical",
        "description": "Prescription/medication data exposed",
    },
    "Health Insurance ID": {
        "regex": r'["\']?(?:insurance_id|policy_number|health_card|member_id)["\']?\s*[:=]\s*["\']?([A-Z0-9\-]{6,20})["\']?',
        "severity": "Critical",
        "category": "Medical",
        "description": "Health insurance ID exposed",
    },
    "Blood Group": {
        "regex": r'["\']?(?:blood_group|blood_type)["\']?\s*[:=]\s*["\']?((?:A|B|AB|O)[+-])["\']?',
        "severity": "High",
        "category": "Medical",
        "description": "Blood group/type in response — medical PII",
    },
    "Patient Name": {
        "regex": r'["\']?(?:patient_name|patient_first_name|patient_last_name)["\']?\s*[:=]\s*["\']([A-Za-z\s]{3,50})["\']',
        "severity": "Critical",
        "category": "Medical",
        "description": "Patient name exposed — HIPAA violation",
    },

    # ── CREDENTIALS & SECRETS ──────────────────────────────────
    "Password in Response": {
        "regex": r'["\']?(?:password|passwd|pwd|pass)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
        "severity": "Critical",
        "category": "Credentials",
        "description": "Password field exposed in API response",
    },
    "API Key Generic": {
        "regex": r'["\']?(?:api_key|apikey|api_token|access_key)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
        "severity": "Critical",
        "category": "Credentials",
        "description": "API key exposed in response",
    },
    "AWS Access Key": {
        "regex": r'\b(AKIA[A-Z0-9]{16})\b',
        "severity": "Critical",
        "category": "Credentials",
        "description": "AWS Access Key ID exposed — cloud account compromise risk",
    },
    "AWS Secret Key": {
        "regex": r'["\']?(?:aws_secret|aws_secret_access_key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+]{40})["\']?',
        "severity": "Critical",
        "category": "Credentials",
        "description": "AWS Secret Access Key exposed",
    },
    "Private Key": {
        "regex": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "severity": "Critical",
        "category": "Credentials",
        "description": "Private cryptographic key exposed in response",
    },
    "JWT Token": {
        "regex": r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
        "severity": "High",
        "category": "Credentials",
        "description": "JWT token exposed — may allow session hijacking",
    },
    "Bearer Token": {
        "regex": r'["\']?(?:token|access_token|auth_token|bearer)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{30,})["\']',
        "severity": "High",
        "category": "Credentials",
        "description": "Authentication token exposed",
    },
    "Database Connection String": {
        "regex": r'(?:mongodb|mysql|postgresql|redis|mssql):\/\/[a-zA-Z0-9_\-]+:[^@\s]+@[a-zA-Z0-9._\-]+',
        "severity": "Critical",
        "category": "Credentials",
        "description": "Database connection string with credentials exposed",
    },
    "Google OAuth": {
        "regex": r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b',
        "severity": "High",
        "category": "Credentials",
        "description": "Google OAuth client ID exposed",
    },
    "Stripe Key": {
        "regex": r'\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b',
        "severity": "Critical",
        "category": "Credentials",
        "description": "Stripe payment API key exposed",
    },
    "Razorpay Key": {
        "regex": r'\brzp_(?:test|live)_[A-Za-z0-9]{14,}\b',
        "severity": "Critical",
        "category": "Credentials",
        "description": "Razorpay payment key exposed",
    },
    "Firebase Config": {
        "regex": r'["\']?(?:apiKey|authDomain|projectId|storageBucket)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "severity": "High",
        "category": "Credentials",
        "description": "Firebase configuration exposed",
    },
}

# ══════════════════════════════════════════════════════════════
# IDOR PATTERNS — responses that indicate user data access
# ══════════════════════════════════════════════════════════════

IDOR_SENSITIVE_FIELDS = [
    "aadhaar", "pan", "ssn", "passport", "credit_card", "card_number",
    "cvv", "pin", "bank_account", "ifsc", "upi", "medical_record",
    "diagnosis", "prescription", "patient_id", "mrn",
    "password", "secret", "private_key", "api_key",
    "date_of_birth", "dob", "address", "phone", "email",
    "salary", "income", "tax_id", "voter_id", "driving_license",
]


def luhn_check(card_num: str) -> bool:
    """Luhn algorithm to validate card numbers"""
    num = card_num.replace(" ", "").replace("-", "")
    if not num.isdigit():
        return False
    total = 0
    reverse = num[::-1]
    for i, digit in enumerate(reverse):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class SensitiveDataScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []
        self._compile_patterns()

    def _compile_patterns(self):
        self._compiled = {}
        for name, info in PATTERNS.items():
            try:
                self._compiled[name] = re.compile(info["regex"], re.IGNORECASE)
            except re.error:
                pass

    async def scan_url(self, url: str) -> List[Finding]:
        """Scan a URL response for sensitive data"""
        resp = await self.http.get(url)
        if not resp:
            return []
        return self._analyze_response(url, "GET", resp.text,
                                       dict(resp.headers))

    async def scan_api_endpoints(self, urls: List[str]) -> List[Finding]:
        """Scan multiple API endpoints"""
        if self.log:
            self.log.info(f"Sensitive data scan: {len(urls)} endpoints")
        tasks = [self.scan_url(u) for u in urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def scan_with_idor(self, base_url: str, id_param: str = "id",
                              start: int = 1, count: int = 10) -> List[Finding]:
        """Test IDOR — cycle through IDs and check for sensitive data leakage"""
        if self.log:
            self.log.info(f"IDOR sensitive data test: {base_url} param={id_param}")

        for i in range(start, start + count):
            parsed = urlparse(base_url)
            qs = parse_qs(parsed.query) if parsed.query else {}
            qs[id_param] = [str(i)]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?" + urlencode({k: v[0] for k, v in qs.items()})
            resp = await self.http.get(test_url)
            if resp and resp.status_code == 200:
                findings = self._analyze_response(test_url, "GET", resp.text,
                                                   dict(resp.headers))
                # Extra: check if response contains IDOR-sensitive fields
                for field in IDOR_SENSITIVE_FIELDS:
                    if field in resp.text.lower():
                        f = Finding(
                            vuln_type="IDOR — Sensitive Data",
                            severity="Critical",
                            url=test_url,
                            method="GET",
                            parameter=id_param,
                            payload=str(i),
                            evidence=f"Response contains sensitive field '{field}' for ID={i}",
                            response_snippet=resp.text[:400],
                            description=f"IDOR exposes sensitive data — field '{field}' accessible by changing {id_param}={i}",
                        )
                        self.findings.append(f)
                        if self.log:
                            self.log.vuln("IDOR", "Critical", test_url,
                                         f"Sensitive field '{field}' at ID={i}")
                        break

        return self.findings

    async def scan_response_body(self, url: str, method: str,
                                  body: str, headers: dict = None) -> List[Finding]:
        """Directly analyze a response body (for use with form/API responses)"""
        return self._analyze_response(url, method, body, headers or {})

    def _analyze_response(self, url: str, method: str,
                          body: str, headers: dict) -> List[Finding]:
        new_findings = []

        # Skip binary / non-text responses
        ct = headers.get("content-type", "").lower()
        if any(t in ct for t in ["image/", "video/", "audio/", "font/",
                                   "application/octet-stream"]):
            return []

        # Parse JSON for deeper analysis
        json_data = None
        if "application/json" in ct or body.lstrip().startswith(("{", "[")):
            try:
                json_data = json.loads(body)
            except Exception:
                pass

        for name, info in PATTERNS.items():
            compiled = self._compiled.get(name)
            if not compiled:
                continue

            matches = compiled.findall(body)
            if not matches:
                continue

            # Apply min_count filter
            min_count = info.get("min_count", 1)
            if len(matches) < min_count:
                continue

            # Luhn validation for card numbers
            if info.get("validate") == "luhn":
                valid_matches = []
                for m in matches:
                    clean = re.sub(r'[\s\-]', '', m if isinstance(m, str) else m[0])
                    if luhn_check(clean):
                        valid_matches.append(m)
                if not valid_matches:
                    continue
                matches = valid_matches

            # Build evidence
            sample = matches[0] if isinstance(matches[0], str) else matches[0][0]
            # Mask sensitive values partially
            masked = self._mask_value(sample, name)
            count_str = f" ({len(matches)} instances)" if len(matches) > 1 else ""

            f = Finding(
                vuln_type=f"Sensitive Data — {info['category']}",
                severity=info["severity"],
                url=url,
                method=method,
                evidence=f"{name}: {masked}{count_str}",
                description=info["description"],
                extra={"pattern_name": name, "category": info["category"],
                       "count": len(matches)},
            )
            new_findings.append(f)
            self.findings.append(f)

            if self.log:
                self.log.vuln(
                    f"Sensitive Data [{info['category']}]",
                    info["severity"], url,
                    f"{name} — {masked}{count_str}"
                )

        return new_findings

    def _mask_value(self, value: str, pattern_name: str) -> str:
        """Partially mask sensitive values in logs"""
        v = str(value).strip()
        if any(t in pattern_name.lower() for t in
               ["card", "cvv", "pin", "password", "secret", "key", "aadhaar", "ssn", "pan"]):
            if len(v) > 6:
                return v[:3] + "*" * (len(v) - 6) + v[-3:]
            return "***"
        return v[:40] + "..." if len(v) > 40 else v


# ══════════════════════════════════════════════════════════════
# API RESPONSE ANALYZER — checks JSON APIs for data exposure
# ══════════════════════════════════════════════════════════════

class APIDataAnalyzer:
    """
    Specifically targets API endpoints that return user/customer data.
    Looks for: user profiles, account info, transaction history,
    medical records, order details etc.
    """

    SENSITIVE_API_PATHS = [
        "/api/user", "/api/users", "/api/profile", "/api/account",
        "/api/me", "/api/customer", "/api/customers",
        "/api/payment", "/api/payments", "/api/transaction",
        "/api/transactions", "/api/order", "/api/orders",
        "/api/medical", "/api/patient", "/api/record",
        "/api/admin/users", "/api/admin/customers",
        "/api/v1/user", "/api/v2/user", "/api/v1/profile",
        "/api/v1/account", "/api/v2/account",
        "/wp-json/wp/v2/users",  # WordPress user enum
        "/rest/user", "/rest/users",
        "/_api/users", "/_api/members",
        "/graphql",  # GraphQL queries
    ]

    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []
        self.data_scanner = SensitiveDataScanner(http_client, logger)

    async def probe_api_endpoints(self, base_url: str) -> List[Finding]:
        """Probe common API paths for data exposure"""
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        if self.log:
            self.log.info(f"API data exposure probe: {root}")

        tasks = []
        for path in self.SENSITIVE_API_PATHS:
            url = root + path
            tasks.append(self._probe_endpoint(url))

        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def _probe_endpoint(self, url: str):
        resp = await self.http.get(url, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        if not resp or resp.status_code in (404, 410):
            return

        # Got a response — analyze it
        if resp.status_code == 200:
            findings = self.data_scanner._analyze_response(
                url, "GET", resp.text, dict(resp.headers))

            # Check if it's a user listing (mass data exposure)
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    # Mass enumeration possible
                    f = Finding(
                        vuln_type="IDOR — Mass Data Exposure",
                        severity="Critical",
                        url=url,
                        method="GET",
                        evidence=f"API returns list of {len(data)} records without auth check",
                        response_snippet=resp.text[:500],
                        description=f"API endpoint returns bulk user/data records — mass PII exposure",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Mass Data Exposure", "Critical", url,
                                     f"{len(data)} records accessible")
            except Exception:
                pass

        elif resp.status_code == 401:
            if self.log:
                self.log.info(f"Auth required: {url} (401)")
        elif resp.status_code == 403:
            if self.log:
                self.log.info(f"Forbidden: {url} (403) — may bypass with headers")
            # Try auth bypass
            await self._try_auth_bypass(url)

    async def _try_auth_bypass(self, url: str):
        """Try common auth bypass techniques"""
        bypass_headers = [
            {"X-Original-URL": url},
            {"X-Rewrite-URL": url},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]
        for hdrs in bypass_headers:
            resp = await self.http.get(url, headers=hdrs)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                f = Finding(
                    vuln_type="Auth Bypass",
                    severity="Critical",
                    url=url,
                    method="GET",
                    parameter=list(hdrs.keys())[0],
                    payload=str(list(hdrs.values())[0]),
                    evidence=f"403 bypassed using header: {hdrs}",
                    response_snippet=resp.text[:300],
                    description=f"Authorization bypass via HTTP header — 403 becomes 200",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("Auth Bypass", "Critical", url,
                                 f"Bypass via {list(hdrs.keys())[0]}")
                # Now scan the bypassed response for sensitive data
                self.data_scanner._analyze_response(url, "GET", resp.text,
                                                    dict(resp.headers))
                break
