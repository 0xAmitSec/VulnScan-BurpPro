"""
VulnScan - DNS Enumeration
Checks: A, AAAA, MX, NS, TXT, CNAME, SOA, zone transfer
"""
import dns.resolver
import dns.zone
import dns.query
from typing import Dict, List, Optional


class DNSEnum:
    def __init__(self, logger=None):
        self.log = logger
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def enumerate(self, domain: str) -> Dict:
        if self.log:
            self.log.recon(f"DNS enumeration: {domain}")

        result = {
            "domain": domain,
            "records": {},
            "zone_transfer": [],
            "dangling_cnames": [],
        }

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                result["records"][rtype] = [str(r) for r in answers]
            except Exception:
                pass

        # Zone transfer attempt
        if "NS" in result["records"]:
            for ns in result["records"]["NS"]:
                zt = self._zone_transfer(domain, ns.rstrip("."))
                if zt:
                    result["zone_transfer"].extend(zt)
                    if self.log:
                        self.log.vuln("Zone Transfer", "High", domain,
                                     f"Zone transfer allowed on {ns}")

        # Check dangling CNAMEs
        if "CNAME" in result["records"]:
            for cname in result["records"]["CNAME"]:
                if self._is_dangling(cname.rstrip(".")):
                    result["dangling_cnames"].append(cname)
                    if self.log:
                        self.log.vuln("Subdomain Takeover", "High", domain,
                                     f"Dangling CNAME: {cname}")

        return result

    def _zone_transfer(self, domain: str, nameserver: str) -> List[str]:
        records = []
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
            for name, node in zone.nodes.items():
                records.append(f"{name}.{domain}")
        except Exception:
            pass
        return records

    def _is_dangling(self, cname: str) -> bool:
        try:
            self.resolver.resolve(cname, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    def get_ip(self, domain: str) -> Optional[str]:
        try:
            answers = self.resolver.resolve(domain, "A")
            return str(answers[0])
        except Exception:
            return None

    def get_all_ips(self, domains: List[str]) -> Dict[str, str]:
        result = {}
        for d in domains:
            ip = self.get_ip(d)
            if ip:
                result[d] = ip
        return result
