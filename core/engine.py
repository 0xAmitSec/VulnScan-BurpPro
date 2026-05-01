"""
VulnScan - Main Scan Engine
Orchestrates all modules: recon, crawl, vuln scan, report
"""
import asyncio
import time
import os
import sys
from datetime import datetime
from typing import List
from urllib.parse import urlparse, parse_qs

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ScanConfig
from core.logger import ScanLogger
from utils.http_client import HTTPClient
from utils.scope_checker import ScopeChecker
from database.models import Finding

from modules.recon.subdomain import SubdomainEnumerator
from modules.recon.dns import DNSEnum
from modules.recon.port_scan import PortScanner
from modules.web.crawler import WebCrawler
from modules.vulns.xss.scanner import XSSScanner
from modules.vulns.sqli.scanner import SQLiScanner
from modules.vulns.ssrf.scanner import SSRFScanner
from modules.vulns.info_disclosure.scanner import InfoDisclosureScanner
from modules.vulns.multi_scanner import (
    CORSScanner, OpenRedirectScanner, LFIScanner,
    SSTIScanner, MisconfigScanner
)
from modules.vulns.sensitive_data.scanner import (
    SensitiveDataScanner, APIDataAnalyzer
)
from reporting.report import generate_html_report, generate_json_report


class VulnScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.start_time = None
        self.findings: List[Finding] = []
        self.recon_data = {}

        # Setup output dir
        os.makedirs(config.output_dir, exist_ok=True)
        os.makedirs(os.path.join(config.output_dir, "logs"), exist_ok=True)
        os.makedirs(os.path.join(config.output_dir, "reports"), exist_ok=True)

        # Logger
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logger = ScanLogger(f"scan_{ts}", config.output_dir)

        # HTTP client
        self.http = HTTPClient(config)

        # Scope checker
        self.scope = ScopeChecker(
            scope_domains=config.scope_domains,
            exclude_domains=config.exclude_domains,
            exclude_paths=config.exclude_paths,
        )

    async def run(self) -> dict:
        self.start_time = time.time()
        target = self.config.target
        if not target.startswith("http"):
            target = "https://" + target
        self.config.target = target

        parsed = urlparse(target)
        domain = parsed.netloc

        self.logger.info(f"VulnScan started")
        self.logger.info(f"Target: {target}")
        self.logger.info(f"Profile: {self.config.profile}")
        self.logger.info(f"Output: {self.config.output_dir}")

        # ── PHASE 1: RECON ──────────────────────────────────────
        if self.config.recon:
            self.logger.info("=" * 50)
            self.logger.info("PHASE 1: RECONNAISSANCE")
            self.logger.info("=" * 50)
            await self._phase_recon(domain, target)

        # ── PHASE 2: WEB CRAWL ──────────────────────────────────
        crawl_data = {"urls": [target], "forms": [], "js_files": [], "endpoints": [], "params": []}
        if self.config.web_crawl:
            self.logger.info("=" * 50)
            self.logger.info("PHASE 2: WEB CRAWLING")
            self.logger.info("=" * 50)
            crawl_data = await self._phase_crawl(target)

        # ── PHASE 3: VULNERABILITY SCANNING ────────────────────
        if self.config.vuln_scan:
            self.logger.info("=" * 50)
            self.logger.info("PHASE 3: VULNERABILITY SCANNING")
            self.logger.info("=" * 50)
            await self._phase_vuln_scan(target, crawl_data)

        # ── PHASE 4: REPORTING ──────────────────────────────────
        self.logger.info("=" * 50)
        self.logger.info("PHASE 4: REPORTING")
        self.logger.info("=" * 50)
        report_paths = await self._phase_report(target)

        duration = round(time.time() - self.start_time, 1)
        self.logger.success(f"Scan complete in {duration}s — {len(self.findings)} findings")

        return {
            "target": target,
            "duration": f"{duration}s",
            "findings": self.findings,
            "reports": report_paths,
            "recon": self.recon_data,
        }

    async def _phase_recon(self, domain: str, target: str):
        # Subdomain enum
        self.logger.recon("Subdomain Enumeration")
        enumerator = SubdomainEnumerator(self.http, self.logger)
        subdomains = await enumerator.enumerate(domain)
        self.recon_data["subdomains"] = subdomains

        # DNS enum
        self.logger.recon("DNS Enumeration")
        dns_enum = DNSEnum(self.logger)
        dns_result = await dns_enum.enumerate(domain)
        self.recon_data["dns"] = dns_result

        # Port scan
        self.logger.recon("Port Scanning")
        scanner = PortScanner(self.logger)
        ip = dns_enum.get_ip(domain) or domain
        open_ports = await scanner.scan(ip)
        self.recon_data["open_ports"] = open_ports

        # Check dangerous services
        dangerous = scanner.check_dangerous_services(open_ports)
        for d in dangerous:
            f = Finding(
                vuln_type="Dangerous Service",
                severity=d["severity"],
                url=f"{ip}:{d['port']}",
                evidence=f"Port {d['port']}/{d['service']} open",
                description=d["description"],
            )
            self.findings.append(f)

        self.logger.success(f"Recon complete: {len(subdomains)} subdomains, {len(open_ports)} open ports")

    async def _phase_crawl(self, target: str) -> dict:
        crawler = WebCrawler(
            http_client=self.http,
            scope_checker=self.scope,
            logger=self.logger,
            max_depth=3 if self.config.profile == "deep" else 2,
            max_urls=500 if self.config.profile == "deep" else 100,
        )
        crawl_data = await crawler.crawl(target)

        # Analyze JS files for secrets
        for js_url in list(crawl_data["js_files"])[:20]:
            js_data = await crawler.analyze_js_file(js_url)
            if js_data.get("secrets"):
                for secret in js_data["secrets"]:
                    f = Finding(
                        vuln_type="Info Disclosure",
                        severity="High",
                        url=js_url,
                        evidence=f"Secret found: {secret['type']} — {secret['value']}",
                        description=f"Hardcoded {secret['type']} found in JavaScript file",
                    )
                    self.findings.append(f)
                    self.logger.vuln("Info Disclosure", "High", js_url,
                                    f"Secret: {secret['type']}")

        self.logger.success(f"Crawl: {len(crawl_data['urls'])} URLs, {len(crawl_data['forms'])} forms")
        return crawl_data

    async def _phase_vuln_scan(self, target: str, crawl_data: dict):
        urls = list(crawl_data.get("urls", [target]))
        forms = crawl_data.get("forms", [])
        urls_with_params = [u for u in urls if "?" in u]

        self.logger.info(f"Scanning {len(urls_with_params)} parameterized URLs, {len(forms)} forms")

        # Info disclosure on main target
        if self.config.check_info_disclosure:
            self.logger.info("Checking information disclosure...")
            info_scanner = InfoDisclosureScanner(self.http, self.logger)
            findings = await info_scanner.scan(target)
            self.findings.extend(findings)

        # Batch URL scanning
        batch_tasks = []

        for url in urls_with_params[:100]:  # Limit for performance
            if self.config.check_xss:
                batch_tasks.append(self._scan_xss_url(url))
            if self.config.check_sqli:
                batch_tasks.append(self._scan_sqli_url(url))
            if self.config.check_ssrf:
                batch_tasks.append(self._scan_ssrf_url(url))
            if self.config.check_ssti:
                batch_tasks.append(self._scan_ssti_url(url))
            if self.config.check_lfi:
                batch_tasks.append(self._scan_lfi_url(url))
            if self.config.check_open_redirect:
                batch_tasks.append(self._scan_redirect_url(url))

        # Run in controlled batches
        batch_size = self.config.threads
        for i in range(0, len(batch_tasks), batch_size):
            await asyncio.gather(*batch_tasks[i:i + batch_size], return_exceptions=True)

        # Form scanning
        for form in forms[:50]:
            if self.config.check_xss:
                xss = XSSScanner(self.http, self.logger)
                self.findings.extend(await xss.scan_form(form))
            if self.config.check_sqli:
                sqli = SQLiScanner(self.http, self.logger)
                self.findings.extend(await sqli.scan_form(form))

        # CORS and misconfig on all unique domains
        unique_origins = set()
        for url in urls[:50]:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in unique_origins:
                unique_origins.add(origin)
                if self.config.check_cors:
                    cors = CORSScanner(self.http, self.logger)
                    self.findings.extend(await cors.scan(url))
                if self.config.check_misconfig:
                    misc = MisconfigScanner(self.http, self.logger)
                    self.findings.extend(await misc.scan(url))

        # ── SENSITIVE DATA SCAN ──────────────────────────────────
        self.logger.info("Scanning for PII / Payment / Medical / Identity data exposure...")

        # 1. Scan all crawled URLs for sensitive data in responses
        sd_scanner = SensitiveDataScanner(self.http, self.logger)
        all_urls = list(crawl_data.get("urls", [target]))
        # Prioritize API and data endpoints
        api_urls = [u for u in all_urls if any(
            kw in u.lower() for kw in
            ["/api/", "/user", "/profile", "/account", "/payment",
             "/order", "/transaction", "/patient", "/medical", "/admin",
             "?id=", "?user_id=", "?uid=", "?customer="])]
        other_urls = [u for u in all_urls if u not in api_urls]

        scan_list = api_urls[:100] + other_urls[:50]
        await sd_scanner.scan_api_endpoints(scan_list)
        self.findings.extend(sd_scanner.findings)

        # 2. Probe known API paths
        api_analyzer = APIDataAnalyzer(self.http, self.logger)
        await api_analyzer.probe_api_endpoints(target)
        self.findings.extend(api_analyzer.findings)

        # 3. IDOR test on parameterized URLs
        idor_scanner = SensitiveDataScanner(self.http, self.logger)
        for url in urls_with_params[:30]:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query) if parsed.query else {}
            for param, val in qs.items():
                v = val[0] if isinstance(val, list) else val
                if str(v).isdigit():
                    await idor_scanner.scan_with_idor(url, param, int(v), count=5)
        self.findings.extend(idor_scanner.findings)

    async def _scan_xss_url(self, url: str):
        try:
            scanner = XSSScanner(self.http, self.logger)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _scan_sqli_url(self, url: str):
        try:
            scanner = SQLiScanner(self.http, self.logger)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _scan_ssrf_url(self, url: str):
        try:
            scanner = SSRFScanner(self.http, self.logger,
                                  oast_url=self.config.oast_server)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _scan_ssti_url(self, url: str):
        try:
            scanner = SSTIScanner(self.http, self.logger)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _scan_lfi_url(self, url: str):
        try:
            scanner = LFIScanner(self.http, self.logger)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _scan_redirect_url(self, url: str):
        try:
            scanner = OpenRedirectScanner(self.http, self.logger)
            self.findings.extend(await scanner.scan_url(url))
        except Exception:
            pass

    async def _phase_report(self, target: str) -> dict:
        duration = f"{round(time.time() - self.start_time, 1)}s"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{self.config.report_name}_{ts}"
        reports = {}

        scan_info = {"duration": duration, "target": target}

        html_path = os.path.join(self.config.output_dir, "reports", f"{base_name}.html")
        generate_html_report(self.findings, target, scan_info, html_path)
        reports["html"] = html_path
        self.logger.success(f"HTML report: {html_path}")

        json_path = os.path.join(self.config.output_dir, "reports", f"{base_name}.json")
        generate_json_report(self.findings, target, json_path)
        reports["json"] = json_path
        self.logger.success(f"JSON report: {json_path}")

        # Print summary
        self.logger.info(f"\n{'='*50}")
        self.logger.info(f"SCAN SUMMARY — {target}")
        self.logger.info(f"{'='*50}")
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        for sev, cnt in counts.items():
            if cnt > 0:
                self.logger.info(f"  {sev}: {cnt}")
        self.logger.info(f"  Total: {len(self.findings)}")
        self.logger.info(f"  Duration: {duration}")

        return reports

    async def close(self):
        await self.http.close()
