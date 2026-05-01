"""
VulnScan - SQL Injection Scanner
Detects: Error-based, Boolean-blind, Time-based, UNION-based
"""
import asyncio
import time
import re
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs
from database.models import Finding
from payloads import SQLI_PAYLOADS, SQLI_TIME_PAYLOADS


ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch_array",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"valid postgresql result",
    r"npgsql\.",
    # MSSQL
    r"unclosed quotation mark",
    r"microsoft.*odbc.*sql server",
    r"microsoft.*ole db.*sql server",
    r"incorrect syntax near",
    r"\[sql server\]",
    # Oracle
    r"oracle error",
    r"ora-[0-9]{4,5}",
    r"oracle.*driver",
    # SQLite
    r"sqlite_exception",
    r"sqlite error",
    r"sqlite3\.",
    # Generic
    r"syntax error.*sql",
    r"sql syntax.*error",
    r"invalid query",
    r"sql command not properly ended",
    r"quoted string not properly terminated",
]


class SQLiScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        if self.log:
            self.log.info(f"SQLi scan: {url}")
        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        if params:
            qs.update(params)
        if not qs:
            return []

        tasks = []
        for param in qs:
            tasks.append(self._test_param(url, param, qs.copy()))
        await asyncio.gather(*tasks)
        return self.findings

    async def _test_param(self, url: str, param: str, qs: dict):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 1. Error-based detection
        for payload in SQLI_PAYLOADS[:8]:
            test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
            test_qs[param] = payload
            test_url = base + "?" + urlencode(test_qs)
            resp = await self.http.get(test_url)
            if resp:
                for pattern in ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        f = Finding(
                            vuln_type="SQL Injection",
                            severity="Critical",
                            url=url,
                            method="GET",
                            parameter=param,
                            payload=payload,
                            evidence=f"DB error pattern matched: {pattern}",
                            request=f"GET {test_url}",
                            response_snippet=resp.text[:500],
                            description=f"Error-based SQLi in parameter '{param}' — DB error revealed",
                        )
                        self.findings.append(f)
                        if self.log:
                            self.log.vuln("SQL Injection", "Critical", url,
                                         f"Error-based — param={param}")
                        return

        # 2. Boolean-based blind detection
        await self._test_boolean_blind(url, base, param, qs)

        # 3. Time-based blind detection
        await self._test_time_based(url, base, param, qs)

    async def _test_boolean_blind(self, url: str, base: str, param: str, qs: dict):
        """Test true vs false condition response difference"""
        orig_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
        orig_val = orig_qs[param]

        true_qs = orig_qs.copy()
        true_qs[param] = f"{orig_val}' AND '1'='1"
        false_qs = orig_qs.copy()
        false_qs[param] = f"{orig_val}' AND '1'='2"

        resp_true = await self.http.get(base + "?" + urlencode(true_qs))
        resp_false = await self.http.get(base + "?" + urlencode(false_qs))

        if resp_true and resp_false:
            # Significant difference in response = boolean SQLi
            len_diff = abs(len(resp_true.text) - len(resp_false.text))
            if len_diff > 50 and resp_true.status_code != resp_false.status_code:
                f = Finding(
                    vuln_type="SQL Injection",
                    severity="Critical",
                    url=url,
                    method="GET",
                    parameter=param,
                    payload=f"' AND '1'='1 vs ' AND '1'='2",
                    evidence=f"Response length diff: {len_diff} bytes (true={len(resp_true.text)}, false={len(resp_false.text)})",
                    description=f"Boolean-based blind SQLi in parameter '{param}'",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("SQL Injection", "Critical", url,
                                 f"Boolean-blind — param={param} diff={len_diff}bytes")

    async def _test_time_based(self, url: str, base: str, param: str, qs: dict):
        orig_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
        orig_val = orig_qs[param]

        for payload_template in SQLI_TIME_PAYLOADS[:3]:
            payload = payload_template.replace("SLEEP(5)", "SLEEP(4)")
            test_qs = orig_qs.copy()
            test_qs[param] = orig_val + payload
            test_url = base + "?" + urlencode(test_qs)

            start = time.time()
            resp = await self.http.get(test_url)
            elapsed = time.time() - start

            if resp and elapsed >= 3.5:
                f = Finding(
                    vuln_type="SQL Injection",
                    severity="Critical",
                    url=url,
                    method="GET",
                    parameter=param,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s — time-based injection confirmed",
                    request=f"GET {test_url}",
                    description=f"Time-based blind SQLi in parameter '{param}' — server delayed {elapsed:.1f}s",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("SQL Injection", "Critical", url,
                                 f"Time-based — param={param} delay={elapsed:.1f}s")
                return

    async def scan_form(self, form: dict) -> List[Finding]:
        url = form["url"]
        method = form["method"]
        fields = form["fields"]

        for field in fields:
            if field["type"] in ("hidden", "submit", "button", "image"):
                continue
            for payload in SQLI_PAYLOADS[:5]:
                data = {f["name"]: f["value"] for f in fields}
                data[field["name"]] = payload
                if method == "POST":
                    resp = await self.http.post(url, data=data)
                else:
                    resp = await self.http.get(url, params=data)
                if resp:
                    for pattern in ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            f = Finding(
                                vuln_type="SQL Injection",
                                severity="Critical",
                                url=url,
                                method=method,
                                parameter=field["name"],
                                payload=payload,
                                evidence=f"DB error in form field",
                                description=f"Error-based SQLi in form field '{field['name']}'",
                            )
                            self.findings.append(f)
                            if self.log:
                                self.log.vuln("SQL Injection", "Critical", url,
                                             f"Form field={field['name']}")
                            break
        return self.findings
