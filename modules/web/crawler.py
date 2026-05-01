"""
VulnScan - Web Crawler
Crawls website, extracts: URLs, forms, params, JS files, endpoints
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Set, List, Dict, Tuple
from bs4 import BeautifulSoup


class WebCrawler:
    def __init__(self, http_client, scope_checker=None, logger=None,
                 max_depth: int = 3, max_urls: int = 500):
        self.http = http_client
        self.scope = scope_checker
        self.log = logger
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited: Set[str] = set()
        self.urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.js_files: Set[str] = set()
        self.endpoints: Set[str] = set()
        self.params: Set[str] = set()

    def normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Remove fragment
        return parsed._replace(fragment="").geturl()

    async def crawl(self, start_url: str) -> Dict:
        if self.log:
            self.log.recon(f"Crawling: {start_url}")
        await self._crawl_url(start_url, depth=0)
        if self.log:
            self.log.success(f"Crawl complete — {len(self.urls)} URLs, {len(self.forms)} forms, {len(self.js_files)} JS files")
        return {
            "urls": list(self.urls),
            "forms": self.forms,
            "js_files": list(self.js_files),
            "endpoints": list(self.endpoints),
            "params": list(self.params),
        }

    async def _crawl_url(self, url: str, depth: int):
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_urls:
            return
        url = self.normalize_url(url)
        if url in self.visited:
            return
        if self.scope and not self.scope.is_in_scope(url):
            return

        self.visited.add(url)
        self.urls.add(url)
        self._extract_params(url)

        resp = await self.http.get(url)
        if not resp:
            return

        ct = resp.headers.get("content-type", "")
        if "html" not in ct and "xml" not in ct:
            return

        soup = BeautifulSoup(resp.text, "lxml")
        new_urls = []

        # Extract all links
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            full = urljoin(url, href)
            full = self.normalize_url(full)
            if full not in self.visited and full.startswith("http"):
                new_urls.append(full)
                self.urls.add(full)
                self._extract_params(full)

        # Extract forms
        for form in soup.find_all("form"):
            form_data = self._parse_form(form, url)
            if form_data:
                self.forms.append(form_data)

        # Extract JS files
        for script in soup.find_all("script", src=True):
            src = urljoin(url, script["src"])
            if src.startswith("http"):
                self.js_files.add(src)

        # Extract from JS inline
        for script in soup.find_all("script"):
            if script.string:
                self._extract_from_js(script.string, url)

        # Extract API endpoints from data attributes
        for tag in soup.find_all(attrs={"data-url": True}):
            full = urljoin(url, tag["data-url"])
            self.urls.add(full)
            self.endpoints.add(full)

        # Crawl found URLs concurrently
        tasks = [self._crawl_url(u, depth + 1) for u in new_urls[:50]]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _parse_form(self, form, base_url: str) -> Dict:
        action = form.get("action", "")
        method = (form.get("method", "GET")).upper()
        action_url = urljoin(base_url, action) if action else base_url
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            itype = inp.get("type", "text")
            value = inp.get("value", "")
            if name:
                fields.append({"name": name, "type": itype, "value": value})
        if not fields:
            return None
        return {
            "url": action_url,
            "method": method,
            "fields": fields,
        }

    def _extract_params(self, url: str):
        try:
            parsed = urlparse(url)
            if parsed.query:
                qs = parse_qs(parsed.query)
                self.params.update(qs.keys())
                self.endpoints.add(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
        except Exception:
            pass

    def _extract_from_js(self, js_text: str, base_url: str):
        # Find API endpoints in JS
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
        ]
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for pattern in patterns:
            matches = re.findall(pattern, js_text)
            for m in matches:
                if m.startswith("/"):
                    full = base + m
                    self.endpoints.add(full)
                elif m.startswith("http"):
                    self.endpoints.add(m)

    async def analyze_js_file(self, js_url: str) -> Dict:
        """Extract secrets and endpoints from a JS file"""
        resp = await self.http.get(js_url)
        if not resp:
            return {}
        text = resp.text
        findings = {"url": js_url, "endpoints": [], "secrets": []}

        # Extract endpoints
        for match in re.findall(r'["\'](/[a-zA-Z0-9_\-/]+(?:\?[^"\']*)?)["\']', text):
            if len(match) > 2:
                findings["endpoints"].append(match)

        # Look for potential secrets
        secret_patterns = [
            (r'api[_-]?key["\s:=]+["\']?([A-Za-z0-9_\-]{20,})', "API Key"),
            (r'secret["\s:=]+["\']?([A-Za-z0-9_\-]{20,})', "Secret"),
            (r'password["\s:=]+["\']?([A-Za-z0-9_\-!@#]{8,})', "Password"),
            (r'token["\s:=]+["\']?([A-Za-z0-9_\-\.]{20,})', "Token"),
            (r'AWS_[A-Z_]+["\s:=]+["\']?([A-Za-z0-9/+]{20,})', "AWS Key"),
            (r'AKIA[A-Z0-9]{16}', "AWS Access Key"),
            (r'["\']Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']', "Bearer Token"),
        ]
        for pattern, label in secret_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                findings["secrets"].append({"type": label, "value": m[:50] + "..."})

        return findings
