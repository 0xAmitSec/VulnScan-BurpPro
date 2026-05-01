"""
VulnScan - Subdomain Enumeration
Uses: DNS brute force + crt.sh + HackerTarget + wayback
"""
import asyncio
import httpx
import dns.resolver
import json
from typing import List, Set
from urllib.parse import urlparse
from payloads import SUBDOMAINS_WORDLIST


class SubdomainEnumerator:
    def __init__(self, http_client=None, logger=None):
        self.http = http_client
        self.log = logger
        self.found: Set[str] = set()

    async def enumerate(self, domain: str) -> List[str]:
        domain = domain.lower().strip()
        if self.log:
            self.log.recon(f"Starting subdomain enumeration for: {domain}")

        tasks = [
            self._crtsh(domain),
            self._hackertarget(domain),
            self._dns_bruteforce(domain),
            self._wayback_subdomains(domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                self.found.update(r)

        found_list = sorted(self.found)
        if self.log:
            self.log.success(f"Found {len(found_list)} subdomains for {domain}")
        return found_list

    async def _crtsh(self, domain: str) -> List[str]:
        subs = []
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower().lstrip("*.")
                            if domain in sub and sub not in subs:
                                subs.append(sub)
        except Exception:
            pass
        return subs

    async def _hackertarget(self, domain: str) -> List[str]:
        subs = []
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={domain}"
                )
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.strip().split("\n"):
                        parts = line.split(",")
                        if parts:
                            sub = parts[0].strip().lower()
                            if domain in sub:
                                subs.append(sub)
        except Exception:
            pass
        return subs

    async def _wayback_subdomains(self, domain: str) -> List[str]:
        subs = []
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(
                    f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        for entry in data[1:]:
                            url = entry[0] if entry else ""
                            parsed = urlparse(url)
                            host = parsed.netloc.lower().split(":")[0]
                            if domain in host:
                                subs.append(host)
                    except Exception:
                        pass
        except Exception:
            pass
        return list(set(subs))

    async def _dns_bruteforce(self, domain: str) -> List[str]:
        subs = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        async def resolve(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                resolver.resolve(fqdn, "A")
                subs.append(fqdn)
            except Exception:
                pass

        tasks = [resolve(w) for w in SUBDOMAINS_WORDLIST]
        # Run in batches
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            await asyncio.gather(*tasks[i:i+batch_size], return_exceptions=True)

        return subs
