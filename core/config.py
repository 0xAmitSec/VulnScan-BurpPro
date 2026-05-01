"""
VulnScan - Core Configuration
"""
import yaml
import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class ScanConfig:
    # Target
    target: str = ""
    targets_file: str = ""

    # Scope
    scope_domains: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)

    # Scan options
    profile: str = "deep"           # quick / deep / api
    threads: int = 20
    timeout: int = 10
    delay: float = 0.2             # seconds between requests
    max_redirects: int = 5
    verify_ssl: bool = False

    # Proxy
    proxy: Optional[str] = None    # http://127.0.0.1:8080

    # Headers
    custom_headers: dict = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"

    # Modules to run
    recon: bool = True
    web_crawl: bool = True
    vuln_scan: bool = True
    active_scan: bool = True

    # Specific vulns
    check_xss: bool = True
    check_sqli: bool = True
    check_ssrf: bool = True
    check_ssti: bool = True
    check_xxe: bool = True
    check_lfi: bool = True
    check_open_redirect: bool = True
    check_cmd_injection: bool = True
    check_idor: bool = True
    check_auth: bool = True
    check_headers: bool = True
    check_cors: bool = True
    check_info_disclosure: bool = True
    check_file_upload: bool = True
    check_cloud: bool = True
    check_advanced: bool = True
    check_misconfig: bool = True

    # Output
    output_dir: str = "output"
    report_format: str = "html"     # html / json / markdown / all
    report_name: str = "vulnscan_report"

    # OAST
    oast_server: str = ""           # interactsh server
    oast_token: str = ""

    # API keys
    shodan_key: str = ""

    # Notifications
    slack_webhook: str = ""
    discord_webhook: str = ""
    telegram_token: str = ""
    telegram_chat_id: str = ""

    @classmethod
    def from_yaml(cls, path: str) -> "ScanConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        cfg = cls()
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        cfg = cls()
        for k, v in data.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    def to_yaml(self, path: str):
        import dataclasses
        with open(path, "w") as f:
            yaml.dump(dataclasses.asdict(self), f, default_flow_style=False)
