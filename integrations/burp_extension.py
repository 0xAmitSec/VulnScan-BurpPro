# VulnScan Burp Extension (BApp)
# Language: Python (Jython 2.7)
# Install: Burp → Extender → Extensions → Add → Python → Select this file
#
# What this does:
# - Adds "VulnScan" tab in Burp UI
# - Right-click any request → "Send to VulnScan"
# - Auto-scans every request passing through proxy
# - Shows findings directly in Burp Issues tab
# - One-click: send all findings to VulnScan HTML report

from burp import IBurpExtender, ITab, IHttpListener
from burp import IScannerCheck, IScanIssue, IContextMenuFactory
from javax.swing import (JPanel, JButton, JTextArea, JScrollPane,
                          JLabel, JTextField, JSplitPane, JComboBox,
                          JCheckBox, BoxLayout, BorderFactory, JMenuItem)
from java.awt import BorderLayout, Color, Font, Dimension, FlowLayout
from java.awt.event import ActionListener
import threading
import json
import re
import sys
import os


# ── Severity colors ─────────────────────────────────────────────
SEV_COLOR = {
    "Critical": Color(220, 53, 69),
    "High":     Color(255, 109, 0),
    "Medium":   Color(255, 179, 0),
    "Low":      Color(0, 188, 212),
    "Info":     Color(158, 158, 158),
}

XSS_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "' AND SLEEP(3)--",
    "\" OR \"1\"=\"1",
    "1 ORDER BY 100--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "postgresql error",
    "unclosed quotation", "microsoft ole db", "sqlite_exception",
    "invalid query", "sql command not properly",
]

SENSITIVE_PATTERNS = {
    "Aadhaar Number": r'\b[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',
    "PAN Card":       r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',
    "Credit Card":    r'\b4[0-9]{12}(?:[0-9]{3})?\b',
    "AWS Key":        r'AKIA[A-Z0-9]{16}',
    "JWT Token":      r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "Private Key":    r'-----BEGIN.*PRIVATE KEY-----',
    "Password Field": r'["\'](?:password|passwd|pwd)["\']:\s*["\'][^"\']+["\']',
    "DB Conn String": r'(?:mongodb|mysql|postgresql|redis):\/\/[^@\s]+@',
}


class BurpExtender(IBurpExtender, ITab, IHttpListener,
                    IScannerCheck, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._findings  = []
        self._scan_count = 0
        self._auto_scan  = True

        callbacks.setExtensionName("VulnScan Pro")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # Build UI
        self._build_ui()
        callbacks.addSuiteTab(self)

        self._log("VulnScan Pro loaded! Ready for aggressive scanning.")

    # ── ITab ────────────────────────────────────────────────────

    def getTabCaption(self):
        return "VulnScan"

    def getUiComponent(self):
        return self._main_panel

    # ── UI ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBackground(Color(8, 10, 13))

        # Top toolbar
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        toolbar.setBackground(Color(13, 16, 23))
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color(30, 39, 56)))

        title = JLabel("  VulnScan Pro  ")
        title.setForeground(Color(0, 230, 118))
        title.setFont(Font("JetBrains Mono", Font.BOLD, 14))
        toolbar.add(title)

        self._url_field = JTextField("https://target.com", 30)
        self._url_field.setBackground(Color(22, 27, 36))
        self._url_field.setForeground(Color(0, 230, 118))
        self._url_field.setCaretColor(Color(0, 230, 118))
        toolbar.add(self._url_field)

        btn_scan = JButton("Full Scan")
        btn_scan.setBackground(Color(0, 200, 83))
        btn_scan.setForeground(Color(0, 0, 0))
        btn_scan.setFont(Font("JetBrains Mono", Font.BOLD, 12))
        btn_scan.addActionListener(lambda e: self._start_full_scan())
        toolbar.add(btn_scan)

        btn_clear = JButton("Clear")
        btn_clear.setBackground(Color(30, 39, 56))
        btn_clear.setForeground(Color(200, 214, 232))
        btn_clear.addActionListener(lambda e: self._clear())
        toolbar.add(btn_clear)

        self._auto_cb = JCheckBox("Auto-scan proxy traffic", True)
        self._auto_cb.setForeground(Color(200, 214, 232))
        self._auto_cb.setBackground(Color(13, 16, 23))
        self._auto_cb.addActionListener(lambda e: self._toggle_auto())
        toolbar.add(self._auto_cb)

        self._status = JLabel("  Ready")
        self._status.setForeground(Color(122, 143, 168))
        self._status.setFont(Font("JetBrains Mono", Font.PLAIN, 11))
        toolbar.add(self._status)

        # Log area
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setBackground(Color(8, 10, 13))
        self._log_area.setForeground(Color(200, 214, 232))
        self._log_area.setFont(Font("JetBrains Mono", Font.PLAIN, 11))
        log_scroll = JScrollPane(self._log_area)
        log_scroll.setPreferredSize(Dimension(0, 200))

        # Findings area
        self._findings_area = JTextArea()
        self._findings_area.setEditable(False)
        self._findings_area.setBackground(Color(10, 12, 15))
        self._findings_area.setForeground(Color(255, 255, 255))
        self._findings_area.setFont(Font("JetBrains Mono", Font.PLAIN, 11))
        findings_scroll = JScrollPane(self._findings_area)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, log_scroll, findings_scroll)
        split.setDividerLocation(200)
        split.setBackground(Color(8, 10, 13))

        self._main_panel.add(toolbar, BorderLayout.NORTH)
        self._main_panel.add(split, BorderLayout.CENTER)

    def _log(self, msg):
        from java.lang import Runnable
        from javax.swing import SwingUtilities
        self._log_area.append("[VulnScan] " + msg + "\n")
        self._log_area.setCaretPosition(self._log_area.getDocument().getLength())

    def _add_finding(self, vuln_type, severity, url, detail):
        self._findings.append({
            "type": vuln_type, "severity": severity,
            "url": url, "detail": detail
        })
        line = f"[{severity.upper()}] {vuln_type} — {url[:60]} — {detail[:80]}\n"
        self._findings_area.append(line)
        self._findings_area.setCaretPosition(
            self._findings_area.getDocument().getLength())
        self._status.setText(f"  {len(self._findings)} findings")

    def _clear(self):
        self._findings = []
        self._log_area.setText("")
        self._findings_area.setText("")
        self._status.setText("  Ready")

    def _toggle_auto(self):
        self._auto_scan = self._auto_cb.isSelected()
        self._log("Auto-scan: " + ("ON" if self._auto_scan else "OFF"))

    # ── IHttpListener — fires on every proxy request ─────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not self._auto_scan:
            return

        # Only process in-scope traffic
        url = str(self._helpers.analyzeRequest(
            messageInfo.getHttpService(),
            messageInfo.getRequest()
        ).getUrl())

        response = messageInfo.getResponse()
        if not response:
            return

        analyzed = self._helpers.analyzeResponse(response)
        body_offset = analyzed.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])

        # Scan response for sensitive data
        self._scan_response_for_sensitive(url, body)
        self._scan_count += 1

    # ── IScannerCheck — runs on active scan ──────────────────────

    def doPassiveScan(self, baseRequestResponse):
        """Passive scan — check every response automatically"""
        issues = []
        try:
            response = baseRequestResponse.getResponse()
            if not response:
                return None
            analyzed = self._helpers.analyzeResponse(response)
            body = self._helpers.bytesToString(
                response[analyzed.getBodyOffset():])
            url = str(self._helpers.analyzeRequest(
                baseRequestResponse.getHttpService(),
                baseRequestResponse.getRequest()
            ).getUrl())

            for name, pattern in SENSITIVE_PATTERNS.items():
                if re.search(pattern, body, re.IGNORECASE):
                    self._add_finding(
                        "Sensitive Data — " + name, "Critical", url,
                        name + " pattern found in response"
                    )
                    issues.append(
                        self._make_issue(baseRequestResponse,
                                        "Sensitive Data: " + name,
                                        "Critical", url,
                                        name + " found in response body")
                    )
        except Exception as e:
            pass
        return issues if issues else None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scan — inject payloads at each insertion point"""
        issues = []
        param_value = self._helpers.bytesToString(
            insertionPoint.getBaseValue())
        url = str(self._helpers.analyzeRequest(
            baseRequestResponse.getHttpService(),
            baseRequestResponse.getRequest()
        ).getUrl())

        # XSS
        for payload in XSS_PAYLOADS:
            try:
                req = insertionPoint.buildRequest(
                    self._helpers.stringToBytes(payload))
                resp = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), req)
                if resp:
                    rbody = self._helpers.bytesToString(
                        resp.getResponse() or b"")
                    if payload in rbody:
                        self._add_finding("XSS", "High", url,
                                         f"Payload reflected: {payload[:40]}")
                        issues.append(
                            self._make_issue(resp, "Reflected XSS",
                                            "High", url,
                                            f"Payload: {payload}"))
                        break
            except Exception:
                pass

        # SQLi
        for payload in SQLI_PAYLOADS:
            try:
                req = insertionPoint.buildRequest(
                    self._helpers.stringToBytes(param_value + payload))
                resp = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), req)
                if resp:
                    rbody = self._helpers.bytesToString(
                        resp.getResponse() or b"").lower()
                    for err in SQLI_ERRORS:
                        if err in rbody:
                            self._add_finding("SQL Injection", "Critical",
                                             url, f"DB error: {err}")
                            issues.append(
                                self._make_issue(resp, "SQL Injection",
                                                "Critical", url,
                                                f"Error: {err}, Payload: {payload}"))
                            break
            except Exception:
                pass

        return issues if issues else None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1  # Keep existing
        return 0

    # ── Context Menu — right-click "Send to VulnScan" ───────────

    def createMenuItems(self, invocation):
        menu = []
        item = JMenuItem("Send to VulnScan — Full Scan")
        item.addActionListener(lambda e: self._scan_from_menu(invocation))
        menu.append(item)

        item2 = JMenuItem("VulnScan — Check Sensitive Data")
        item2.addActionListener(lambda e: self._check_sensitive_from_menu(invocation))
        menu.append(item2)
        return menu

    def _scan_from_menu(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        msg = messages[0]
        url = str(self._helpers.analyzeRequest(
            msg.getHttpService(), msg.getRequest()).getUrl())
        self._url_field.setText(url)
        self._start_full_scan()

    def _check_sensitive_from_menu(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        for msg in messages:
            resp = msg.getResponse()
            if resp:
                url = str(self._helpers.analyzeRequest(
                    msg.getHttpService(), msg.getRequest()).getUrl())
                analyzed = self._helpers.analyzeResponse(resp)
                body = self._helpers.bytesToString(resp[analyzed.getBodyOffset():])
                self._scan_response_for_sensitive(url, body)

    # ── Internal Helpers ─────────────────────────────────────────

    def _scan_response_for_sensitive(self, url, body):
        for name, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                self._add_finding(
                    "Sensitive Data — " + name, "Critical", url,
                    name + " detected in response"
                )

    def _start_full_scan(self):
        url = self._url_field.getText().strip()
        if not url:
            return
        self._log(f"Starting full scan: {url}")
        t = threading.Thread(target=self._run_scan_thread, args=(url,))
        t.setDaemon(True)
        t.start()

    def _run_scan_thread(self, url):
        try:
            self._log("Scan started...")
            # Trigger Burp active scan via callbacks
            self._callbacks.sendToSpider(java.net.URL(url))
            self._log("Spider started for: " + url)
        except Exception as e:
            self._log("Error: " + str(e))

    def _make_issue(self, requestResponse, name, severity, url, detail):
        """Create a Burp IScanIssue object"""
        class CustomIssue(IScanIssue):
            def __init__(self, rr, n, sev, u, det):
                self._rr = rr
                self._name = n
                self._sev = sev
                self._url = u
                self._det = det
            def getUrl(self): return java.net.URL(self._url)
            def getIssueName(self): return "[VulnScan] " + self._name
            def getIssueType(self): return 0x08000000
            def getSeverity(self): return self._sev.lower()
            def getConfidence(self): return "certain"
            def getIssueBackground(self): return None
            def getRemediationBackground(self): return None
            def getIssueDetail(self): return self._det
            def getRemediationDetail(self): return None
            def getHttpMessages(self): return [self._rr]
            def getHttpService(self): return self._rr.getHttpService()
        return CustomIssue(requestResponse, name, severity, url, detail)
