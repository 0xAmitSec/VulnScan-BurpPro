"""
VulnScan - Port Scanner
Fast async TCP port scanner with service detection
"""
import asyncio
import socket
from typing import Dict, List, Tuple


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
    2375: "Docker",
    2376: "Docker-TLS",
    6443: "Kubernetes",
    9090: "Prometheus",
    3000: "Grafana/Node",
    4000: "Node-Alt",
    5000: "Flask/Python",
    8000: "Django/Python",
    8081: "HTTP-Alt",
    9000: "PHP-FPM",
    10250: "Kubelet",
}


class PortScanner:
    def __init__(self, logger=None, timeout: float = 1.5, max_workers: int = 200):
        self.log = logger
        self.timeout = timeout
        self.max_workers = max_workers

    async def scan(self, host: str, ports: List[int] = None) -> Dict[int, str]:
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        if self.log:
            self.log.recon(f"Port scanning {host} ({len(ports)} ports)")

        sem = asyncio.Semaphore(self.max_workers)
        open_ports = {}

        async def check_port(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    service = COMMON_PORTS.get(port, "Unknown")
                    open_ports[port] = service
                    if self.log:
                        self.log.info(f"Open port: {host}:{port} ({service})")
                except Exception:
                    pass

        await asyncio.gather(*[check_port(p) for p in ports])

        if self.log:
            self.log.success(f"Found {len(open_ports)} open ports on {host}")
        return dict(sorted(open_ports.items()))

    async def scan_range(self, host: str, start: int = 1, end: int = 65535) -> Dict[int, str]:
        ports = list(range(start, end + 1))
        return await self.scan(host, ports)

    def check_dangerous_services(self, open_ports: Dict[int, str]) -> List[Dict]:
        dangerous = []
        dangerous_ports = {
            21: ("FTP", "Medium", "FTP often transmits credentials in plaintext"),
            23: ("Telnet", "High", "Telnet transmits all data including credentials in plaintext"),
            25: ("SMTP", "Low", "Open SMTP relay check recommended"),
            445: ("SMB", "High", "SMB exposure can lead to EternalBlue-type attacks"),
            3389: ("RDP", "High", "RDP exposure — BlueKeep and brute force risk"),
            5900: ("VNC", "High", "VNC often weakly authenticated"),
            6379: ("Redis", "Critical", "Redis with no auth — direct code execution possible"),
            9200: ("Elasticsearch", "High", "Elasticsearch often has no auth enabled"),
            27017: ("MongoDB", "High", "MongoDB often has no auth enabled"),
            11211: ("Memcached", "Medium", "Memcached amplification and info leak risk"),
            2375: ("Docker", "Critical", "Unauthenticated Docker API — full host compromise"),
        }
        for port, service in open_ports.items():
            if port in dangerous_ports:
                name, sev, desc = dangerous_ports[port]
                dangerous.append({
                    "port": port,
                    "service": name,
                    "severity": sev,
                    "description": desc,
                })
        return dangerous
