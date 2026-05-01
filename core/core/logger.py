"""
VulnScan - Structured Logger
"""
import logging
import os
from datetime import datetime
from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler

console = Console(theme=Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warn":    "bold yellow",
    "danger":  "bold red",
    "vuln":    "bold red on white",
    "recon":   "bold blue",
    "dim":     "dim white",
}))

def get_logger(name: str, log_file: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    # Rich console handler
    ch = RichHandler(console=console, show_time=True, show_path=False, markup=True)
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    # File handler
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        logger.addHandler(fh)

    return logger


class ScanLogger:
    def __init__(self, scan_id: str, output_dir: str = "output"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(output_dir, "logs", f"{scan_id}_{ts}.log")
        self.logger = get_logger(f"vulnscan.{scan_id}", log_file)
        self._findings = []

    def info(self, msg):
        self.logger.info(f"[info]{msg}[/info]")

    def success(self, msg):
        self.logger.info(f"[success]{msg}[/success]")

    def warn(self, msg):
        self.logger.warning(f"[warn]{msg}[/warn]")

    def error(self, msg):
        self.logger.error(f"[danger]{msg}[/danger]")

    def recon(self, msg):
        self.logger.info(f"[recon][RECON][/recon] {msg}")

    def vuln(self, vuln_type: str, severity: str, url: str, detail: str):
        sev_color = {
            "Critical": "[bold red]",
            "High":     "[red]",
            "Medium":   "[yellow]",
            "Low":      "[cyan]",
            "Info":     "[dim]",
        }.get(severity, "[white]")
        msg = f"{sev_color}[{severity}][/{sev_color[1:]} [{vuln_type}] {url} — {detail}"
        self.logger.warning(msg)
        self._findings.append({
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "detail": detail,
            "timestamp": datetime.now().isoformat()
        })

    def get_findings(self):
        return self._findings
