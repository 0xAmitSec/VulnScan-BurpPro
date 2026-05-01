"""
VulnScan - HTML Report Generator
Generates professional penetration test report
"""
import json
import os
from datetime import datetime
from typing import List
from database.models import Finding, SEVERITY_ORDER


def generate_html_report(findings: List[Finding], target: str,
                         scan_info: dict = None, output_path: str = "report.html") -> str:
    findings_sorted = sorted(findings, key=lambda f: f.severity_order())

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings_sorted:
        if f.severity in counts:
            counts[f.severity] += 1

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = scan_info.get("duration", "N/A") if scan_info else "N/A"

    def sev_badge(sev):
        colors = {
            "Critical": "#ff5252", "High": "#ff6d00",
            "Medium": "#ffb300", "Low": "#00bcd4", "Info": "#9e9e9e"
        }
        c = colors.get(sev, "#9e9e9e")
        return f'<span style="background:{c};color:#fff;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700">{sev}</span>'

    findings_html = ""
    for i, f in enumerate(findings_sorted):
        cat = f.extra.get("category", "") if f.extra else ""
        cat_badge = ""
        if cat:
            cat_colors = {
                "Payment": "#ff5252", "Identity": "#ce93d8",
                "Medical": "#00bcd4", "PII": "#ffb300",
                "Credentials": "#ff6d00",
            }
            cc = cat_colors.get(cat, "#607d8b")
            cat_badge = f'<span style="background:{cc}22;color:{cc};border:1px solid {cc}44;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;font-family:monospace">{cat}</span>'

        findings_html += f"""
        <div class="finding" id="f-{f.id}" data-sev="{f.severity}" data-cat="{cat}">
          <div class="finding-header" onclick="toggle('fb-{f.id}')">
            <div class="finding-title">
              {sev_badge(f.severity)}
              {cat_badge}
              <span class="finding-name">{f.vuln_type}</span>
              <span class="finding-url">{f.url[:80]}{'...' if len(f.url)>80 else ''}</span>
            </div>
            <div class="finding-meta">
              <span>{f.cwe}</span>
              <span>CVSS {f.cvss_score}</span>
              <span>&#9660;</span>
            </div>
          </div>
          <div class="finding-body" id="fb-{f.id}">
            <div class="finding-grid">
              <div class="finding-detail"><h4>Description</h4><p>{f.description or 'N/A'}</p></div>
              <div class="finding-detail"><h4>Evidence</h4><pre class="code">{f.evidence or 'N/A'}</pre></div>
              {'<div class="finding-detail"><h4>Parameter</h4><code>' + f.parameter + '</code></div>' if f.parameter else ''}
              {'<div class="finding-detail"><h4>Payload Used</h4><pre class="code">' + f.payload + '</pre></div>' if f.payload else ''}
              {'<div class="finding-detail"><h4>Request</h4><pre class="code">' + f.request + '</pre></div>' if f.request else ''}
              {'<div class="finding-detail"><h4>Response Snippet</h4><pre class="code">' + (f.response_snippet or '')[:400] + '</pre></div>' if f.response_snippet else ''}
              <div class="finding-detail remediation"><h4>&#128737; Remediation</h4><p>{f.remediation or 'Review and fix the identified issue'}</p></div>
            </div>
            <div class="finding-footer">
              <span>ID: {f.id}</span><span>Method: {f.method}</span>
              <span>CWE: {f.cwe}</span><span>CVSS: {f.cvss_score}</span>
              <span>{f.timestamp[:19]}</span>
            </div>
          </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VulnScan Report — {target}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0a0c0f;color:#c8d6e8;font-family:'Space Grotesk',sans-serif;padding:30px}}
.header{{background:linear-gradient(135deg,#0d1f17,#0f1a2e);border:1px solid #1e3a2a;border-radius:12px;padding:30px;margin-bottom:24px}}
.header h1{{font-size:28px;color:#00e676;font-family:'JetBrains Mono',monospace;margin-bottom:6px}}
.header-meta{{display:flex;gap:20px;margin-top:16px;flex-wrap:wrap}}
.meta-item{{background:rgba(0,230,118,.08);border:1px solid rgba(0,230,118,.15);border-radius:6px;padding:8px 14px}}
.meta-item span{{display:block;font-size:10px;color:#3d4f66;font-family:'JetBrains Mono',monospace;text-transform:uppercase;margin-bottom:3px}}
.meta-item strong{{font-size:14px;color:#00e676}}
.summary{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}}
.scard{{border-radius:8px;padding:20px;text-align:center;border:1px solid}}
.scard-C{{background:rgba(255,82,82,.1);border-color:rgba(255,82,82,.3)}}
.scard-H{{background:rgba(255,109,0,.1);border-color:rgba(255,109,0,.3)}}
.scard-M{{background:rgba(255,179,0,.1);border-color:rgba(255,179,0,.3)}}
.scard-L{{background:rgba(0,188,212,.1);border-color:rgba(0,188,212,.3)}}
.scard-I{{background:rgba(158,158,158,.1);border-color:rgba(158,158,158,.3)}}
.scard .num{{font-size:36px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.scard-C .num{{color:#ff5252}}.scard-H .num{{color:#ff6d00}}
.scard-M .num{{color:#ffb300}}.scard-L .num{{color:#00bcd4}}.scard-I .num{{color:#9e9e9e}}
.scard .label{{font-size:11px;color:#7a8fa8;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}}
.section-title{{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:#00e676;text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #1e2738}}
.finding{{background:#111318;border:1px solid #1e2738;border-radius:8px;margin-bottom:10px;overflow:hidden}}
.finding-header{{padding:14px 18px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;transition:background .15s}}
.finding-header:hover{{background:#161b24}}
.finding-title{{display:flex;align-items:center;gap:12px;flex-wrap:wrap}}
.finding-name{{font-weight:600;font-size:14px;color:#c8d6e8}}
.finding-url{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#7a8fa8}}
.finding-meta{{display:flex;gap:12px;align-items:center;font-size:11px;color:#3d4f66;font-family:'JetBrains Mono',monospace;flex-shrink:0}}
.toggle-btn{{color:#7a8fa8;font-size:12px}}
.finding-body{{display:none;border-top:1px solid #1e2738;padding:18px}}
.finding-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}}
.finding-detail{{background:#0a0c0f;border:1px solid #1e2738;border-radius:6px;padding:12px}}
.finding-detail h4{{font-size:10px;font-weight:700;color:#7a8fa8;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;font-family:'JetBrains Mono',monospace}}
.finding-detail p{{font-size:12px;line-height:1.6;color:#c8d6e8}}
.finding-detail.remediation{{background:rgba(0,230,118,.05);border-color:rgba(0,230,118,.15);grid-column:1/-1}}
.finding-detail.remediation p{{color:#00e676}}
pre.code{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#ffb300;white-space:pre-wrap;word-break:break-all;line-height:1.5}}
code{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#ce93d8;background:#0a0c0f;padding:2px 6px;border-radius:3px}}
.finding-footer{{display:flex;gap:14px;font-family:'JetBrains Mono',monospace;font-size:9px;color:#3d4f66;padding-top:10px;border-top:1px solid #1e2738;flex-wrap:wrap}}
.no-findings{{padding:40px;text-align:center;color:#3d4f66;font-family:'JetBrains Mono',monospace}}
.filter-bar{{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}}
.filter-btn{{padding:5px 12px;border-radius:4px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid #1e2738;background:transparent;color:#7a8fa8;font-family:'JetBrains Mono',monospace;transition:all .15s}}
.filter-btn.active{{background:rgba(0,230,118,.1);color:#00e676;border-color:rgba(0,230,118,.25)}}
@media(max-width:700px){{.summary{{grid-template-columns:1fr 1fr}}.finding-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<div class="header">
  <h1>&#128737; VulnScan Security Report</h1>
  <div style="color:#7a8fa8;font-size:13px;margin-top:4px">Vulnerability Assessment Report — Ethical Security Testing</div>
  <div class="header-meta">
    <div class="meta-item"><span>Target</span><strong>{target}</strong></div>
    <div class="meta-item"><span>Scan Date</span><strong>{scan_date}</strong></div>
    <div class="meta-item"><span>Duration</span><strong>{duration}</strong></div>
    <div class="meta-item"><span>Total Findings</span><strong>{len(findings_sorted)}</strong></div>
    <div class="meta-item"><span>Tool</span><strong>VulnScan v1.0</strong></div>
  </div>
</div>

<div class="summary">
  <div class="scard scard-C"><div class="num">{counts['Critical']}</div><div class="label">Critical</div></div>
  <div class="scard scard-H"><div class="num">{counts['High']}</div><div class="label">High</div></div>
  <div class="scard scard-M"><div class="num">{counts['Medium']}</div><div class="label">Medium</div></div>
  <div class="scard scard-L"><div class="num">{counts['Low']}</div><div class="label">Low</div></div>
  <div class="scard scard-I"><div class="num">{counts['Info']}</div><div class="label">Info</div></div>
</div>

<div class="section-title">Findings ({len(findings_sorted)} total)</div>

<div class="filter-bar">
  <button class="filter-btn active" onclick="filterFindings('all','all',this)">All ({len(findings_sorted)})</button>
  <button class="filter-btn" onclick="filterFindings('Critical','all',this)">&#128308; Critical ({counts['Critical']})</button>
  <button class="filter-btn" onclick="filterFindings('High','all',this)">&#128992; High ({counts['High']})</button>
  <button class="filter-btn" onclick="filterFindings('Medium','all',this)">&#128993; Medium ({counts['Medium']})</button>
  <button class="filter-btn" onclick="filterFindings('all','Payment',this)">&#128179; Payment</button>
  <button class="filter-btn" onclick="filterFindings('all','Identity',this)">&#128100; Identity</button>
  <button class="filter-btn" onclick="filterFindings('all','Medical',this)">&#128138; Medical</button>
  <button class="filter-btn" onclick="filterFindings('all','PII',this)">&#128203; PII</button>
  <button class="filter-btn" onclick="filterFindings('all','Credentials',this)">&#128273; Credentials</button>
</div>

<div id="findings-container">
  {''.join([findings_html]) if findings_sorted else '<div class="no-findings">No findings recorded</div>'}
</div>

<script>
function toggle(id){{
  var el=document.getElementById(id);
  el.style.display=el.style.display==='block'?'none':'block';
}}
function filterFindings(sev,cat,btn){{
  document.querySelectorAll('.filter-btn').forEach(function(b){{b.classList.remove('active');}});
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(function(f){{
    var fSev=f.getAttribute('data-sev');
    var fCat=f.getAttribute('data-cat');
    var sevOk = sev==='all' || fSev===sev;
    var catOk = cat==='all' || fCat===cat;
    f.style.display=(sevOk&&catOk)?'block':'none';
  }});
}}
// Expand all critical by default
document.querySelectorAll('.finding[data-sev="Critical"] .finding-body').forEach(function(b){{b.style.display='block';}});
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_json_report(findings: List[Finding], target: str,
                         output_path: str = "report.json") -> str:
    data = {
        "tool": "VulnScan",
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "Critical"),
            "high": sum(1 for f in findings if f.severity == "High"),
            "medium": sum(1 for f in findings if f.severity == "Medium"),
            "low": sum(1 for f in findings if f.severity == "Low"),
        },
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: x.severity_order())]
    }
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(data, fh, indent=2)
    return output_path
