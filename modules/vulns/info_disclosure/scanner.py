"""
VulnScan - Information Disclosure Scanner
Checks: .git, .env, backup files, directory listing, error pages, server headers
"""
import asyncio
import re
from typing import List
from urllib.parse import urljoin, urlparse
from database.models import Finding
from payloads import SENSITIVE_FILES, BACKUP_EXTENSIONS


class InfoDisclosureScanner:
    def __init__(self, http_client, logger=None):
        self.http = http_client
        self.log = logger
        self.findings: List[Finding] = []

    async def scan(self, url: str) -> List[Finding]:
        if self.log:
            self.log.info(f"Info disclosure scan: {url}")

        tasks = [
            self._check_sensitive_files(url),
            self._check_backup_files(url),
            self._check_directory_listing(url),
            self._check_server_headers(url),
            self._check_error_disclosure(url),
            self._check_git_exposure(url),
            self._check_env_exposure(url),
        ]
        await asyncio.gather(*tasks)
        return self.findings

    async def _check_sensitive_files(self, base_url: str):
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        async def check(path):
            url = root + path
            resp = await self.http.get(url)
            if not resp or resp.status_code in (404, 403, 410):
                return

            if resp.status_code == 200 and len(resp.text) > 10:
                sev, desc = self._classify_sensitive_file(path, resp.text)
                if sev:
                    f = Finding(
                        vuln_type="Info Disclosure",
                        severity=sev,
                        url=url,
                        method="GET",
                        evidence=f"Sensitive file accessible: {path}",
                        response_snippet=resp.text[:300],
                        description=desc,
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Info Disclosure", sev, url, f"Accessible: {path}")

        tasks = [check(p) for p in SENSITIVE_FILES]
        batch_size = 30
        for i in range(0, len(tasks), batch_size):
            await asyncio.gather(*tasks[i:i+batch_size])

    def _classify_sensitive_file(self, path: str, content: str):
        if ".git" in path:
            if "ref:" in content or "[core]" in content or "repositoryformatversion" in content:
                return "Critical", ".git directory exposed — full source code dump possible via git-dumper"
        if ".env" in path:
            if any(k in content for k in ["DB_", "APP_KEY", "SECRET", "PASSWORD", "TOKEN", "AWS_"]):
                return "Critical", ".env file exposed — credentials and secrets visible"
            return "High", ".env file accessible"
        if path in ("/phpinfo.php", "/info.php"):
            if "PHP Version" in content:
                return "Medium", "PHP info page exposed — server configuration leaked"
        if "wp-config.php" in path:
            if "DB_PASSWORD" in content or "DB_NAME" in content:
                return "Critical", "WordPress config exposed — DB credentials visible"
        if path in ("/robots.txt",):
            return "Info", "robots.txt found — may reveal hidden paths"
        if path in ("/crossdomain.xml", "/clientaccesspolicy.xml"):
            if "<allow-access-from" in content:
                return "Medium", "Permissive crossdomain policy"
        if "swagger" in path.lower() or "api-docs" in path.lower():
            return "Medium", "API documentation publicly exposed"
        if "/graphql" in path:
            return "Medium", "GraphQL endpoint exposed"
        if path in ("/server-status", "/server-info"):
            return "Medium", "Apache server status exposed"
        if path in ("/elmah.axd", "/trace.axd"):
            return "High", "ASP.NET error log exposed"
        if path == "/docker-compose.yml" or path == "/Dockerfile":
            return "High", "Docker configuration file exposed"
        if path in ("/composer.json", "/composer.lock", "/package.json"):
            return "Low", "Dependency file exposed — reveals technology stack"
        if any(path.endswith(ext) for ext in [".bak", ".old", ".backup"]):
            return "High", "Backup file exposed — may contain sensitive data"
        if content and len(content) > 50:
            return "Low", f"File accessible: {path}"
        return None, None

    async def _check_backup_files(self, base_url: str):
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        common_files = [
            "index.php", "config.php", "settings.php", "database.php",
            "wp-config.php", "web.config", "app.py", "config.py",
            "application.rb", "database.yml",
        ]
        for fname in common_files:
            for ext in BACKUP_EXTENSIONS:
                path = f"/{fname}{ext}"
                url = root + path
                resp = await self.http.get(url)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    sev = "High" if any(k in resp.text for k in
                                       ["password", "secret", "key", "token", "DB_"]) else "Medium"
                    f = Finding(
                        vuln_type="Backup File",
                        severity=sev,
                        url=url,
                        method="GET",
                        evidence=f"Backup file accessible: {fname}{ext}",
                        response_snippet=resp.text[:200],
                        description=f"Backup file '{fname}{ext}' is publicly accessible",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Backup File", sev, url, f"{fname}{ext}")

    async def _check_directory_listing(self, url: str):
        dirs_to_check = ["/", "/images/", "/uploads/", "/files/", "/static/",
                         "/assets/", "/backup/", "/admin/", "/logs/"]
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        for d in dirs_to_check:
            check_url = root + d
            resp = await self.http.get(check_url)
            if resp and resp.status_code == 200:
                if re.search(r'Index of /', resp.text) or \
                   re.search(r'<title>Index of', resp.text) or \
                   re.search(r'Directory listing for', resp.text):
                    f = Finding(
                        vuln_type="Directory Listing",
                        severity="Medium",
                        url=check_url,
                        method="GET",
                        evidence=f"Directory listing enabled at {d}",
                        response_snippet=resp.text[:300],
                        description=f"Web server directory listing enabled — shows all files in {d}",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Directory Listing", "Medium", check_url, d)

    async def _check_server_headers(self, url: str):
        resp = await self.http.head(url)
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check for version disclosure
        if "server" in headers:
            server = headers["server"]
            if re.search(r'[\d\.]+', server):
                f = Finding(
                    vuln_type="Info Disclosure",
                    severity="Low",
                    url=url,
                    method="HEAD",
                    evidence=f"Server header: {server}",
                    description=f"Server version disclosed in header: {server}",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("Info Disclosure", "Low", url, f"Server: {server}")

        if "x-powered-by" in headers:
            powered = headers["x-powered-by"]
            f = Finding(
                vuln_type="Info Disclosure",
                severity="Low",
                url=url,
                method="HEAD",
                evidence=f"X-Powered-By: {powered}",
                description=f"Technology stack disclosed: {powered}",
            )
            self.findings.append(f)

        # Security headers check
        missing = []
        security_headers = {
            "x-frame-options": "Clickjacking protection",
            "x-content-type-options": "MIME sniffing protection",
            "strict-transport-security": "HSTS",
            "content-security-policy": "XSS/injection protection",
            "referrer-policy": "Referrer information control",
        }
        for h, desc in security_headers.items():
            if h not in headers:
                missing.append(f"{h} ({desc})")

        if missing:
            f = Finding(
                vuln_type="Security Headers",
                severity="Medium",
                url=url,
                method="HEAD",
                evidence=f"Missing headers: {', '.join(missing)}",
                description=f"Security headers missing: {', '.join(missing)}",
            )
            self.findings.append(f)
            if self.log:
                self.log.vuln("Security Headers", "Medium", url, f"{len(missing)} missing")

    async def _check_error_disclosure(self, url: str):
        # Trigger 404 with random path
        error_url = url.rstrip("/") + "/vulnscan_nonexistent_path_12345"
        resp = await self.http.get(error_url)
        if resp:
            if any(kw in resp.text for kw in [
                "stack trace", "Traceback (most recent", "Exception in thread",
                "at com.", "at java.", "Laravel\\", "Symfony\\",
                "/home/", "/var/www/", "C:\\inetpub", "C:\\xampp",
            ]):
                f = Finding(
                    vuln_type="Info Disclosure",
                    severity="Medium",
                    url=error_url,
                    method="GET",
                    evidence="Stack trace or internal path in error response",
                    response_snippet=resp.text[:500],
                    description="Server reveals internal paths or stack traces in error responses",
                )
                self.findings.append(f)
                if self.log:
                    self.log.vuln("Info Disclosure", "Medium", url, "Stack trace in errors")

    async def _check_git_exposure(self, url: str):
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        git_paths = ["/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD"]
        for path in git_paths:
            git_url = root + path
            resp = await self.http.get(git_url)
            if resp and resp.status_code == 200 and resp.text.strip():
                if ("ref:" in resp.text or "[core]" in resp.text or
                        "repositoryformatversion" in resp.text or
                        "commit" in resp.text.lower()):
                    f = Finding(
                        vuln_type="Git Exposed",
                        severity="Critical",
                        url=git_url,
                        method="GET",
                        evidence=f"Git object accessible: {path}\n{resp.text[:200]}",
                        description="Exposed .git directory — full source code recoverable using git-dumper",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Git Exposed", "Critical", root, f".git at {path}")
                    return

    async def _check_env_exposure(self, url: str):
        parsed = urlparse(url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        env_paths = ["/.env", "/.env.local", "/.env.backup", "/.env.production",
                     "/.env.development", "/.env.staging"]
        for path in env_paths:
            env_url = root + path
            resp = await self.http.get(env_url)
            if resp and resp.status_code == 200 and "=" in resp.text:
                if any(k in resp.text.upper() for k in
                       ["DB_", "PASSWORD", "SECRET", "KEY", "TOKEN", "AWS_", "API_"]):
                    f = Finding(
                        vuln_type="Env Exposed",
                        severity="Critical",
                        url=env_url,
                        method="GET",
                        evidence=f"Credentials found in {path}",
                        response_snippet=resp.text[:300],
                        description=f"Environment file with credentials exposed at {path}",
                    )
                    self.findings.append(f)
                    if self.log:
                        self.log.vuln("Env Exposed", "Critical", root, f".env at {path}")
                    return
