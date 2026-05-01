"""
VulnScan - XSS Scanner
Detects: Reflected XSS, Stored XSS patterns, DOM XSS indicators
"""
import re
import asyncio
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from database.models import Finding
from payloads import XSS_PAYLOADS


REFLECTION_MARKER = "VULNSCAN_XSS_"
DOM_SINKS = [
    "document.write", "innerHTML", "outerHTML", "insertAdjacentHTML",
    "eval(", "setTimeout(", "setInterval(", "document.cookie",
    "location.href", "location.assign", "location.replace",
    "window.location", "document.URL", "document.referrer",
]


class XSSScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan_url(self, url: str, params: dict = None) -> List[Finding]:
        if self.log:
            self.log.info(f"XSS scan: {url}")

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

    async def scan_form(self, form: dict) -> List[Finding]:
        url = form["url"]
        method = form["method"]
        fields = form["fields"]

        for field in fields:
            if field["type"] in ("hidden", "submit", "button", "image", "reset"):
                continue
            for payload in XSS_PAYLOADS[:10]:  # Test first 10 payloads
                data = {f["name"]: f["value"] for f in fields}
                data[field["name"]] = payload
                if method == "POST":
                    resp = await self.http.post(url, data=data)
                else:
                    resp = await self.http.get(url, params=data)
                if resp and payload in resp.text:
                    f = Finding(
                        vuln_type="Reflected XSS",
                        severity="High",
                        url=url,
                        method=method,
                        parameter=field["name"],
                        payload=payload,
                        evidence=f"Payload reflected in response",
                        description=f"XSS payload reflected in form field '{field['name']}'",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Reflected XSS", "High", url,
                                     f"param={field['name']} payload={payload[:30]}")
                    break  # One finding per field
        return self.findings

    async def _test_param(self, url: str, param: str, qs: dict):
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in XSS_PAYLOADS:
            test_qs = {k: (v[0] if isinstance(v, list) else v) for k, v in qs.items()}
            test_qs[param] = payload
            test_url = base + "?" + urlencode(test_qs)

            resp = await self.http.get(test_url)
            if not resp:
                continue

            # Check if payload reflected unencoded
            if payload in resp.text:
                # Confirm it's in HTML context (not just in source)
                if self._is_xss_context(payload, resp.text):
                    f = Finding(
                        vuln_type="Reflected XSS",
                        severity="High",
                        url=url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        evidence=self._extract_context(payload, resp.text),
                        request=f"GET {test_url}",
                        response_snippet=resp.text[:500],
                        description=f"XSS payload reflected unencoded in parameter '{param}'",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Reflected XSS", "High", url,
                                     f"param={param} payload={payload[:40]}")
                    return  # One finding per param

    def _is_xss_context(self, payload: str, html: str) -> bool:
        """Check if payload is reflected in executable context"""
        # Not inside HTML comment
        comment_pattern = re.compile(r'<!--.*?-->', re.DOTALL)
        clean = comment_pattern.sub('', html)
        if payload in clean:
            return True
        return False

    def _extract_context(self, payload: str, html: str) -> str:
        idx = html.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - 100)
        end = min(len(html), idx + len(payload) + 100)
        return html[start:end]

    async def check_dom_xss(self, js_content: str, url: str) -> List[Finding]:
        findings = []
        for sink in DOM_SINKS:
            if sink in js_content:
                # Look for user-controlled input nearby
                idx = js_content.find(sink)
                context = js_content[max(0, idx-200):idx+200]
                if any(src in context for src in ["location", "URL", "search", "hash",
                                                   "referrer", "input", "param"]):
                    f = Finding(
                        vuln_type="DOM XSS",
                        severity="High",
                        url=url,
                        method="GET",
                        evidence=f"Dangerous sink '{sink}' with user-controlled source",
                        description=f"Potential DOM XSS via {sink}",
                        response_snippet=context,
                    )
                    findings.append(f)
                    if self.log:
                        self.log.vuln("DOM XSS", "High", url, f"sink={sink}")
        return findings
