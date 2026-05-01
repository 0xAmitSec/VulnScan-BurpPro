"""
VulnScan - Scope Checker
"""
import re
from urllib.parse import urlparse
from typing import List


class ScopeChecker:
    def __init__(self, scope_domains: List[str] = None,
                 exclude_domains: List[str] = None,
                 exclude_paths: List[str] = None):
        self.scope_domains = [d.lower().lstrip("*.") for d in (scope_domains or [])]
        self.exclude_domains = [d.lower().lstrip("*.") for d in (exclude_domains or [])]
        self.exclude_paths = exclude_paths or []

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower().split(":")[0]
            path = parsed.path

            # Check exclude domains
            for ex in self.exclude_domains:
                if host == ex or host.endswith("." + ex):
                    return False

            # Check exclude paths
            for ep in self.exclude_paths:
                if re.search(ep, path):
                    return False

            # Check scope — if no scope defined, everything in scope
            if not self.scope_domains:
                return True

            for domain in self.scope_domains:
                if host == domain or host.endswith("." + domain):
                    return True

            return False
        except Exception:
            return False

    def filter_urls(self, urls: List[str]) -> List[str]:
        return [u for u in urls if self.is_in_scope(u)]
