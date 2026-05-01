#!/usr/bin/env python3
"""
VulnScan — Aggressive Smart Scanner with Burp Suite Pro Integration
Usage: python main.py -u https://target.com [options]
"""
import asyncio
import sys
import os
import click
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import ScanConfig
from core.engine import VulnScanEngine
from integrations.burp import (BurpAPIClient, BurpCollaboratorClient,
                                AggressiveBurpScanner)

console = Console()

BANNER = r"""
 __   __      _       _____
 \ \ / /     | |     /  ___|
  \ V / _   _| |_ __ \ `--.  ___ __ _ _ __
  /   \| | | | | '_ \ `--. \/ __/ _` | '_ \
 / /^\ \ |_| | | | | /\__/ / (_| (_| | | | |
 \/   \/\__,_|_|_| |_\____/ \___\__,_|_| |_|
    Aggressive Web Vulnerability Scanner v2.0
    Burp Suite Pro Edition  |  Ethical Use Only
"""


@click.command()
@click.option("--url",     "-u", required=True, help="Target URL")
@click.option("--profile", "-p", default="deep",
              type=click.Choice(["quick","deep","api"]))
@click.option("--threads", "-t", default=20)
@click.option("--timeout",       default=10)
@click.option("--delay",         default=0.1)
@click.option("--proxy",         default="http://127.0.0.1:8080")
@click.option("--scope",   "-s", multiple=True)
@click.option("--exclude", "-e", multiple=True)
@click.option("--output",  "-o", default="output")
@click.option("--header",  "-H", multiple=True)
@click.option("--no-ssl-verify",  is_flag=True)
@click.option("--report-name",    default="vulnscan_report")
@click.option("--burp-api",       default="http://127.0.0.1:1337",
              help="Burp REST API URL")
@click.option("--burp-key",       default="",
              help="Burp REST API key (from Burp User Options)")
@click.option("--burp-collab",    default="",
              help="Burp Collaborator host for blind detection")
@click.option("--burp-scan",      is_flag=True,
              help="Trigger Burp active scanner")
@click.option("--burp-sitemap",   is_flag=True,
              help="Pull URLs already in Burp proxy sitemap")
@click.option("--aggressive",     is_flag=True,
              help="Maximum aggression — all modules, blind OOB, IDOR, threads=50")
def main(url, profile, threads, timeout, delay, proxy, scope, exclude,
         output, header, no_ssl_verify, report_name,
         burp_api, burp_key, burp_collab, burp_scan, burp_sitemap, aggressive):
    """
    VulnScan with Burp Suite Pro — Maximum Coverage

    \b
    Examples:
      # Basic (routes through Burp proxy automatically)
      python main.py -u https://target.com

      # Full Burp integration
      python main.py -u https://target.com
        --burp-api http://127.0.0.1:1337
        --burp-key YOUR_API_KEY
        --burp-collab abc123.burpcollaborator.net
        --burp-scan --aggressive

      # With auth token
      python main.py -u https://target.com
        -H "Cookie: session=abc123"
        -H "Authorization: Bearer TOKEN"
        --aggressive
    """
    console.print(f"[bold green]{BANNER}[/bold green]")

    cfg = ScanConfig()
    cfg.target          = url
    cfg.profile         = "deep" if aggressive else profile
    cfg.threads         = 50 if aggressive else threads
    cfg.timeout         = timeout
    cfg.delay           = 0.05 if aggressive else delay
    cfg.proxy           = proxy
    cfg.scope_domains   = list(scope) or [_domain(url)]
    cfg.exclude_domains = list(exclude)
    cfg.output_dir      = output
    cfg.verify_ssl      = not no_ssl_verify
    cfg.report_name     = report_name

    if header:
        for h in header:
            if ":" in h:
                k, _, v = h.partition(":")
                cfg.custom_headers[k.strip()] = v.strip()

    # Store Burp config as extra attrs
    cfg.burp_api_url  = burp_api
    cfg.burp_api_key  = burp_key
    cfg.burp_collab   = burp_collab
    cfg.burp_scan     = burp_scan or aggressive
    cfg.burp_sitemap  = burp_sitemap or aggressive
    cfg.aggressive    = aggressive

    mode_label = "[bold red]AGGRESSIVE MODE[/bold red]" if aggressive else "[bold green]Scan Config[/bold green]"
    border = "red" if aggressive else "green"

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan]       {url}\n"
        f"[bold cyan]Mode:[/bold cyan]         {'AGGRESSIVE (all modules, max threads)' if aggressive else profile}\n"
        f"[bold cyan]Proxy:[/bold cyan]        {proxy}\n"
        f"[bold cyan]Burp API:[/bold cyan]     {burp_api} "
        f"{'[green]KEY SET[/green]' if burp_key else '[yellow]no key — limited[/yellow]'}\n"
        f"[bold cyan]Collaborator:[/bold cyan] {burp_collab or '[yellow]not set — blind vulns need this[/yellow]'}\n"
        f"[bold cyan]Active Scan:[/bold cyan]  {'[red]YES[/red]' if cfg.burp_scan else 'NO'}\n"
        f"[bold cyan]Sitemap Sync:[/bold cyan] {'YES' if cfg.burp_sitemap else 'NO'}\n"
        f"[bold cyan]Threads:[/bold cyan]      {cfg.threads} | Delay: {cfg.delay}s",
        title=mode_label, border_style=border
    ))

    try:
        asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        console.print("\n[bold red]Stopped.[/bold red]")


async def _run(cfg: ScanConfig):
    engine = VulnScanEngine(cfg)
    try:
        result = await engine.run()
        burp_findings = []

        if getattr(cfg, "burp_scan", False):
            console.print("\n[bold green]Connecting to Burp Suite Pro REST API...[/bold green]")

            burp_client = BurpAPIClient(
                api_url=getattr(cfg, "burp_api_url", "http://127.0.0.1:1337"),
                api_key=getattr(cfg, "burp_api_key", ""),
                logger=engine.logger,
            )

            collab = None
            if getattr(cfg, "burp_collab", ""):
                collab = BurpCollaboratorClient(
                    collaborator_host=cfg.burp_collab,
                    burp_api=burp_client,
                    logger=engine.logger,
                )

            # Collect extra URLs from Burp sitemap
            extra_urls = []
            if getattr(cfg, "burp_sitemap", False):
                extra_urls = await burp_client.extract_urls_from_sitemap(cfg.target)

            # Combine all discovered URLs
            crawled  = list(set(f.url for f in result.get("findings", [])))
            combined = list(set(extra_urls + crawled))[:100]

            aggressive_scanner = AggressiveBurpScanner(
                http_client=engine.http,
                burp_api=burp_client,
                collaborator=collab,
                logger=engine.logger,
            )

            burp_findings = await aggressive_scanner.full_scan(
                cfg.target, extra_urls=combined)

            await burp_client.close()

        # Merge + final report
        if burp_findings:
            from reporting.report import generate_html_report, generate_json_report
            from datetime import datetime
            all_findings = result["findings"] + burp_findings
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = f"{cfg.report_name}_BURP_{ts}"
            html_p = os.path.join(cfg.output_dir, "reports", f"{base}.html")
            json_p = os.path.join(cfg.output_dir, "reports", f"{base}.json")
            generate_html_report(all_findings, cfg.target, {}, html_p)
            generate_json_report(all_findings, cfg.target, json_p)
            console.print(f"\n[green]Final merged report:[/green] {html_p}")
            result["reports"]["html"] = html_p

        total = len(result["findings"]) + len(burp_findings)
        console.print(Panel(
            f"[bold green]Complete![/bold green]\n\n"
            f"[cyan]VulnScan:[/cyan]   {len(result['findings'])} findings\n"
            f"[cyan]Burp Pro:[/cyan]   {len(burp_findings)} findings\n"
            f"[cyan]Total:[/cyan]      {total}\n"
            f"[cyan]Duration:[/cyan]   {result['duration']}\n"
            f"[cyan]Report:[/cyan]     {result['reports'].get('html', 'N/A')}",
            title="Results", border_style="green"
        ))
    finally:
        await engine.close()


def _domain(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).netloc


if __name__ == "__main__":
    main()
