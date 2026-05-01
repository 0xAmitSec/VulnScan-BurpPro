"""
VulnScan - Multiple Vuln Scanners
CORS, Open Redirect, LFI, SSTI, Command Injection, Misconfig
"""
import asyncio
import re
import time
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from database.models import Finding
from payloads import (OPEN_REDIRECT_PAYLOADS, LFI_PAYLOADS,
                      SSTI_PAYLOADS, CMD_INJECTION_PAYLOADS)


# ─── CORS Scanner ───────────────────────────────────────────────
class CORSScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan(self, url: str) -> List[Finding]:
        test_origins = [
            "https://evil.com",
            "https://evil.target.com",
            "null",
            "https://target.com.evil.com",
        ]
        for origin in test_origins:
            resp = await self.http.get(url, headers={"Origin": origin})
            if not resp:
                continue
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if origin in acao or acao == "*":
                sev = "High" if acac.lower() == "true" else "Medium"
                f = Finding(
                    vuln_type="CORS",
                    severity=sev,
                    url=url,
                    method="GET",
                    parameter="Origin header",
                    payload=origin,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description=f"CORS misconfiguration — Origin '{origin}' reflected with credentials={'true' if sev=='High' else 'false'}",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("CORS", sev, url, f"Origin={origin} ACAO={acao}")
        return self.findings


# ─── Open Redirect Scanner ────────────────────────────────────────
class OpenRedirectScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan_url(self, url: str) -> List[Finding]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        redirect_params = {k: v for k, v in qs.items()
                          if any(kw in k.lower() for kw in
                                 ["url", "redirect", "return", "next", "dest",
                                  "destination", "target", "redir", "ref",
                                  "continue", "go", "link", "to"])}
        if not redirect_params:
            return []

        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS[:6]:
                test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
                test_qs[param] = payload
                test_url = base + "?" + urlencode(test_qs)
                resp = await self.http.get(test_url)
                if not resp:
                    continue
                final_url = str(resp.url)
                location = resp.headers.get("location", "")
                if "evil.com" in final_url or "evil.com" in location:
                    f = Finding(
                        vuln_type="Open Redirect",
                        severity="Medium",
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=f"Redirected to: {final_url or location}",
                        description=f"Open redirect via parameter '{param}'",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Open Redirect", "Medium", url, f"param={param}")
                    break
        return self.findings


# ─── LFI Scanner ─────────────────────────────────────────────────
class LFIScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan_url(self, url: str) -> List[Finding]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        file_params = {k: v for k, v in qs.items()
                      if any(kw in k.lower() for kw in
                             ["file", "path", "page", "template", "doc",
                              "document", "include", "load", "read", "view",
                              "content", "lang", "locale", "module"])}
        if not file_params:
            return []

        lfi_indicators = [
            "root:x:", "daemon:x:", "[extensions]", "for 16-bit app support",
            "<?php", "DB_PASSWORD", "DB_HOST",
        ]

        for param in file_params:
            for payload in LFI_PAYLOADS[:15]:
                test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
                test_qs[param] = payload
                test_url = base + "?" + urlencode(test_qs)
                resp = await self.http.get(test_url)
                if not resp:
                    continue
                for indicator in lfi_indicators:
                    if indicator in resp.text:
                        f = Finding(
                            vuln_type="LFI",
                            severity="Critical",
                            url=url,
                            method="GET",
                            parameter=param,
                            payload=payload,
                            evidence=f"LFI indicator found: {indicator}",
                            response_snippet=resp.text[:400],
                            description=f"Local File Inclusion in parameter '{param}' — can read server files",
                        )
                        self.findings.append(f)
                        if self.log:
                            self.log.vuln("LFI", "Critical", url,
                                         f"param={param} indicator={indicator}")
                        return self.findings
        return self.findings


# ─── SSTI Scanner ─────────────────────────────────────────────────
class SSTIScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan_url(self, url: str) -> List[Finding]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if not qs:
            return []

        for param in qs:
            for payload in SSTI_PAYLOADS["generic"]:
                test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
                test_qs[param] = payload
                test_url = base + "?" + urlencode(test_qs)
                resp = await self.http.get(test_url)
                if resp and "49" in resp.text:  # 7*7=49
                    f = Finding(
                        vuln_type="SSTI",
                        severity="Critical",
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=f"Math expression evaluated: {payload} = 49",
                        response_snippet=resp.text[:400],
                        description=f"Server-Side Template Injection in '{param}' — code execution possible",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("SSTI", "Critical", url, f"param={param} payload={payload}")
                    break
        return self.findings


# ─── Misconfig Scanner ───────────────────────────────────────────
class MisconfigScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan(self, url: str) -> List[Finding]:
        await asyncio.gather(
            self._check_http_methods(url),
            self._check_clickjacking(url),
        )
        return self.findings

    async def _check_http_methods(self, url: str):
        dangerous_methods = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH"]
        for method in dangerous_methods:
            resp = await self.http.request(method, url)
            if resp and resp.status_code not in (405, 501, 400, 403):
                sev = "High" if method in ("PUT", "DELETE") else "Medium"
                f = Finding(
                    vuln_type="Misconfig",
                    severity=sev,
                    url=url,
                    method=method,
                    evidence=f"{method} returned {resp.status_code}",
                    description=f"HTTP method {method} enabled — status {resp.status_code}",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("Misconfig", sev, url, f"{method} allowed ({resp.status_code})")

    async def _check_clickjacking(self, url: str):
        resp = await self.http.get(url)
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        has_xfo = "x-frame-options" in headers
        has_csp = "content-security-policy" in headers
        csp_val = headers.get("content-security-policy", "")
        has_csp_frame = "frame-ancestors" in csp_val

        if not has_xfo and not has_csp_frame:
            f = Finding(
                vuln_type="Clickjacking",
                severity="Medium",
                url=url,
                evidence="X-Frame-Options and CSP frame-ancestors both missing",
                description="Page can be embedded in iframe — clickjacking attack possible",
            )
            self.findings.append(f)
            if self.log:
                self.log.vuln("Clickjacking", "Medium", url, "X-Frame-Options missing")
