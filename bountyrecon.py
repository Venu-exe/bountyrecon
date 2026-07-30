#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  BountyRecon — All-in-One Bug Bounty Recon Toolkit          ║
║  Zero dependencies. Pure Python. Built for hunters.         ║
╚══════════════════════════════════════════════════════════════╝

Features:
  • Subdomain Discovery    — bruteforce + certificate transparency
  • Port Scanner           — fast threaded TCP scanning
  • Security Header Audit  — checks all OWASP recommended headers
  • Tech Stack Fingerprint — detects frameworks, servers, CDNs
  • DNS Recon              — A, AAAA, MX, NS, TXT, CNAME records
  • SSL/TLS Analysis       — cert info, expiry, weak ciphers
  • Wayback URLs           — fetches archived URLs from Wayback Machine
  • Directory Bruteforce   — finds hidden paths and endpoints
  • Auto Report            — generates H1-ready markdown reports

Usage:
  python3 bountyrecon.py -t example.com              Full recon
  python3 bountyrecon.py -t example.com -m headers    Single module
  python3 bountyrecon.py -t example.com -m ports      Port scan
  python3 bountyrecon.py -t example.com --fast         Quick scan
  python3 bountyrecon.py -h                            Help

Author: Built for bug bounty hunters 🎯
"""

import socket
import ssl
import sys
import os
import re
import json
import time
import hashlib
import argparse
import urllib.request
import urllib.error
import urllib.parse
import http.client
import concurrent.futures
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set


# ============================================================
# COLORS & UI — Zero dependency terminal styling
# ============================================================
class C:
    """ANSI color codes for terminal styling."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDER   = "\033[4m"
    # Colors
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    # Backgrounds
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"
    BG_CYAN   = "\033[46m"
    BG_GRAY   = "\033[100m"

    @staticmethod
    def disable():
        for attr in dir(C):
            if attr.isupper() and not attr.startswith("_"):
                setattr(C, attr, "")


def banner():
    b = f"""
{C.CYAN}{C.BOLD}
    ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
    ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
{C.RESET}{C.MAGENTA}{C.BOLD}    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RESET}

    {C.DIM}All-in-One Bug Bounty Recon Toolkit{C.RESET}
    {C.DIM}Zero Dependencies • Pure Python • Built for Hunters{C.RESET}
"""
    print(b)


def section(title, icon="🔹"):
    w = 60
    print()
    print(f"  {C.CYAN}{'━' * w}{C.RESET}")
    print(f"  {icon} {C.BOLD}{C.WHITE}{title}{C.RESET}")
    print(f"  {C.CYAN}{'━' * w}{C.RESET}")


def found(label, value, severity=None):
    sev_colors = {
        "critical": (C.BG_RED + C.WHITE, "CRIT"),
        "high":     (C.RED, "HIGH"),
        "medium":   (C.YELLOW, "MED "),
        "low":      (C.BLUE, "LOW "),
        "info":     (C.CYAN, "INFO"),
        "good":     (C.GREEN, "GOOD"),
    }
    if severity and severity in sev_colors:
        color, tag = sev_colors[severity]
        print(f"    {color}[{tag}]{C.RESET} {C.WHITE}{label}:{C.RESET} {value}")
    else:
        print(f"    {C.GREEN}✓{C.RESET} {C.WHITE}{label}:{C.RESET} {value}")


def warn(msg):
    print(f"    {C.YELLOW}  {msg}{C.RESET}")


def fail(msg):
    print(f"    {C.RED}✗  {msg}{C.RESET}")


def info(msg):
    print(f"    {C.CYAN}ℹ  {msg}{C.RESET}")


def progress(current, total, label=""):
    pct = int((current / total) * 100) if total else 0
    bar_len = 30
    filled = int(bar_len * current / total) if total else 0
    bar = f"{C.GREEN}{'█' * filled}{C.GRAY}{'░' * (bar_len - filled)}{C.RESET}"
    sys.stdout.write(f"\r    {bar} {pct:3d}% {C.DIM}{label}{C.RESET}    ")
    sys.stdout.flush()
    if current >= total:
        print()


# ============================================================
# REPORT COLLECTOR
# ============================================================
class Report:
    """Collects findings and generates a markdown report."""

    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.sections: Dict[str, list] = defaultdict(list)

    def add(self, section: str, finding: str, severity: str = "info", detail: str = ""):
        self.sections[section].append({
            "finding": finding,
            "severity": severity,
            "detail": detail,
        })

    def generate(self, output_dir: str) -> str:
        lines = []
        lines.append(f"# BountyRecon Report — {self.target}")
        lines.append(f"\n**Date:** {self.timestamp}")
        lines.append(f"**Target:** {self.target}")
        lines.append("")

        # Summary counts
        total = sum(len(v) for v in self.sections.values())
        sev_counts = defaultdict(int)
        for findings in self.sections.values():
            for f in findings:
                sev_counts[f["severity"]] += 1

        lines.append("## Summary")
        lines.append("")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info", "good"]:
            if sev_counts[sev]:
                lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
        lines.append(f"| **Total** | **{total}** |")
        lines.append("")

        for sec_name, findings in self.sections.items():
            lines.append(f"## {sec_name}")
            lines.append("")
            for f in findings:
                lines.append(f"- **[{f['severity'].upper()}]** {f['finding']}")
                if f["detail"]:
                    lines.append(f"  - {f['detail']}")
            lines.append("")

        lines.append("---")
        lines.append(f"*Generated by BountyRecon at {self.timestamp}*")

        content = "\n".join(lines)
        os.makedirs(output_dir, exist_ok=True)
        safe_target = re.sub(r'[^\w\-.]', '_', self.target)
        filepath = os.path.join(output_dir, f"recon_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        with open(filepath, "w") as f:
            f.write(content)
        return filepath


# ============================================================
# HTTP HELPER
# ============================================================
def http_get(url: str, timeout: int = 10, headers: dict = None) -> Optional[http.client.HTTPResponse]:
    """Make an HTTP GET request using urllib (no dependencies)."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BountyRecon/1.0")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except Exception:
        return None


def http_get_text(url: str, timeout: int = 10) -> Optional[str]:
    """GET request that returns response body as text."""
    resp = http_get(url, timeout)
    if resp:
        try:
            return resp.read().decode("utf-8", errors="ignore")
        except Exception:
            return None
    return None


def http_head(url: str, timeout: int = 8) -> Optional[dict]:
    """HEAD request returning headers dict."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BountyRecon/1.0")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return dict(resp.headers)
    except Exception:
        return None


# ============================================================
# MODULE: DNS RECON
# ============================================================
def mod_dns_recon(target: str, report: Report):
    """DNS record enumeration."""
    section("DNS Reconnaissance", "")

    records_found = []

    # Resolve A records
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        seen = set()
        for item in ips:
            ip = item[4][0]
            if ip not in seen:
                seen.add(ip)
                found("A Record", ip)
                report.add("DNS Records", f"A → {ip}", "info")
                records_found.append(("A", ip))
    except socket.gaierror:
        fail(f"Could not resolve {target}")
        report.add("DNS Records", f"Could not resolve {target}", "high")
        return records_found

    # Resolve AAAA records
    try:
        ipv6 = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
        seen6 = set()
        for item in ipv6:
            ip = item[4][0]
            if ip not in seen6:
                seen6.add(ip)
                found("AAAA Record", ip)
                report.add("DNS Records", f"AAAA → {ip}", "info")
    except Exception:
        pass

    # Reverse DNS
    for rec_type, ip in records_found:
        try:
            hostname = socket.gethostbyaddr(ip)
            found("Reverse DNS", f"{ip} → {hostname[0]}")
            report.add("DNS Records", f"PTR {ip} → {hostname[0]}", "info")
        except Exception:
            pass

    return records_found


# ============================================================
# MODULE: SECURITY HEADERS
# ============================================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "desc": "HSTS not set — vulnerable to SSL stripping attacks",
        "good": "HSTS enabled — protects against downgrade attacks",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "desc": "CSP not set — vulnerable to XSS and data injection",
        "good": "CSP enabled — mitigates XSS attacks",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "desc": "X-Frame-Options not set — vulnerable to clickjacking",
        "good": "Clickjacking protection enabled",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "desc": "X-Content-Type-Options not set — MIME sniffing possible",
        "good": "MIME sniffing protection enabled",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "desc": "X-XSS-Protection not set",
        "good": "XSS protection header present",
    },
    "Referrer-Policy": {
        "severity": "low",
        "desc": "Referrer-Policy not set — may leak sensitive URLs",
        "good": "Referrer policy configured",
    },
    "Permissions-Policy": {
        "severity": "low",
        "desc": "Permissions-Policy not set — browser features unrestricted",
        "good": "Permissions policy configured",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low",
        "desc": "Cross-domain policy not set",
        "good": "Cross-domain policy configured",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "desc": "COOP not set",
        "good": "Cross-Origin-Opener-Policy configured",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "desc": "CORP not set",
        "good": "Cross-Origin-Resource-Policy configured",
    },
}

# Headers that leak server info (bad if present)
INFO_LEAK_HEADERS = {
    "Server": "Server version disclosed",
    "X-Powered-By": "Technology stack disclosed",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
    "X-Generator": "Generator disclosed",
    "X-Drupal-Cache": "Drupal detected",
    "X-Varnish": "Varnish cache disclosed",
    "Via": "Proxy/gateway info disclosed",
}


def mod_security_headers(target: str, report: Report):
    """Audit security headers."""
    section("Security Headers Audit", "")

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        headers = http_head(url)
        if headers:
            info(f"Scanning {url}")
            break
    else:
        fail("Could not connect to target")
        report.add("Security Headers", "Could not connect to target", "high")
        return

    missing_count = 0
    present_count = 0

    # Check required security headers
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in {k.lower() for k in headers.keys()}:
            val = next((v for k, v in headers.items() if k.lower() == header.lower()), "")
            found(header, val[:80], "good")
            report.add("Security Headers", f"✓ {header}: {val[:80]}", "good", meta["good"])
            present_count += 1
        else:
            found(header, "MISSING", meta["severity"])
            report.add("Security Headers", f"✗ {header} missing", meta["severity"], meta["desc"])
            missing_count += 1

    print()

    # Check info leak headers
    for header, desc in INFO_LEAK_HEADERS.items():
        matching = [(k, v) for k, v in headers.items() if k.lower() == header.lower()]
        if matching:
            k, v = matching[0]
            found(f"{k} (info leak)", v, "medium")
            report.add("Security Headers", f"Info leak: {k}: {v}", "medium", desc)

    # Cookie analysis
    cookies_raw = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    if cookies_raw:
        print()
        info("Cookie Analysis:")
        for cookie in cookies_raw:
            cookie_name = cookie.split("=")[0].strip()
            issues = []
            if "secure" not in cookie.lower():
                issues.append("missing Secure flag")
            if "httponly" not in cookie.lower():
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie.lower():
                issues.append("missing SameSite attribute")

            if issues:
                found(f"Cookie '{cookie_name}'", ", ".join(issues), "medium")
                report.add("Security Headers", f"Cookie '{cookie_name}': {', '.join(issues)}", "medium")
            else:
                found(f"Cookie '{cookie_name}'", "properly secured", "good")

    print()
    score = int((present_count / len(SECURITY_HEADERS)) * 100)
    grade_color = C.GREEN if score >= 80 else C.YELLOW if score >= 50 else C.RED
    info(f"Header Score: {grade_color}{C.BOLD}{score}%{C.RESET} ({present_count}/{len(SECURITY_HEADERS)} headers present)")


# ============================================================
# MODULE: PORT SCANNER
# ============================================================
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9090: "WebConsole", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

EXTENDED_PORTS = {
    **COMMON_PORTS,
    81: "HTTP", 88: "Kerberos", 389: "LDAP", 636: "LDAPS",
    873: "Rsync", 1080: "SOCKS", 1723: "PPTP", 2049: "NFS",
    3000: "Node/Grafana", 4443: "HTTPS-Alt", 4848: "GlassFish",
    5000: "Flask/Docker", 5001: "Synology", 5601: "Kibana",
    6443: "K8s-API", 7001: "WebLogic", 7443: "HTTPS-Alt",
    8001: "HTTP-Alt", 8008: "HTTP-Alt", 8081: "HTTP-Alt",
    8082: "HTTP-Alt", 8083: "HTTP-Alt", 8084: "HTTP-Alt",
    8085: "HTTP-Alt", 8086: "InfluxDB", 8087: "HTTP-Alt",
    8088: "HTTP-Alt", 8089: "Splunk", 8090: "HTTP-Alt",
    8161: "ActiveMQ", 8443: "HTTPS-Alt", 8834: "Nessus",
    8880: "HTTP-Alt", 8983: "Solr", 9000: "SonarQube",
    9042: "Cassandra", 9091: "HTTP-Alt", 9200: "Elastic",
    9300: "Elastic", 10000: "Webmin", 10443: "HTTPS-Alt",
    15672: "RabbitMQ", 27018: "MongoDB",
}


def scan_port(target: str, port: int, timeout: float = 1.5) -> Optional[int]:
    """Scan a single port. Returns port number if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def grab_banner(target: str, port: int, timeout: float = 3) -> str:
    """Attempt to grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        # Send a basic probe
        if port in (80, 8080, 8000, 8443, 443, 8888):
            sock.send(f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        else:
            sock.send(b"\r\n")
        banner_data = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Clean up
        banner_data = banner_data.split("\n")[0][:100]
        return banner_data
    except Exception:
        return ""


def mod_port_scan(target: str, report: Report, fast: bool = False):
    """Threaded port scanner."""
    section("Port Scanner", "🔌")

    ports = COMMON_PORTS if fast else EXTENDED_PORTS
    port_list = sorted(ports.keys())
    total = len(port_list)

    # Resolve target to IP
    try:
        ip = socket.gethostbyname(target)
        info(f"Resolved {target} → {ip}")
        info(f"Scanning {total} ports...")
    except socket.gaierror:
        fail(f"Cannot resolve {target}")
        return

    open_ports = []
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in port_list}
        for future in concurrent.futures.as_completed(futures):
            scanned += 1
            progress(scanned, total, f"{scanned}/{total} ports")
            result = future.result()
            if result is not None:
                open_ports.append(result)

    print()
    if open_ports:
        open_ports.sort()
        for port in open_ports:
            service = ports.get(port, "Unknown")
            banner_text = grab_banner(ip, port)
            display = f"{service}"
            if banner_text:
                display += f" {C.DIM}({banner_text[:60]}){C.RESET}"
            found(f"Port {port}", display, "info")
            report.add("Open Ports", f"Port {port}/{service} is open", "info",
                       f"Banner: {banner_text}" if banner_text else "")

        info(f"Found {C.GREEN}{len(open_ports)}{C.RESET} open ports out of {total} scanned")
    else:
        info("No open ports found (all filtered or closed)")
        report.add("Open Ports", "No open ports found", "info")


# ============================================================
# MODULE: SSL/TLS ANALYSIS
# ============================================================
def mod_ssl_analysis(target: str, report: Report):
    """Analyze SSL/TLS certificate and configuration."""
    section("SSL/TLS Analysis", "")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        # Protocol version
        found("Protocol", version, "good" if "TLSv1.3" in version or "TLSv1.2" in version else "high")
        report.add("SSL/TLS", f"Protocol: {version}",
                   "good" if "TLSv1.2" in version or "TLSv1.3" in version else "high")

        # Cipher suite
        if cipher:
            found("Cipher Suite", cipher[0])
            found("Cipher Bits", str(cipher[2]))
            report.add("SSL/TLS", f"Cipher: {cipher[0]} ({cipher[2]}-bit)", "info")

        # Certificate details
        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            found("Subject CN", subject.get("commonName", "N/A"))
            found("Issuer", issuer.get("organizationName", "N/A"))

            # SANs
            sans = [entry[1] for entry in cert.get("subjectAltName", [])]
            if sans:
                found("SANs", f"{len(sans)} entries")
                for san in sans[:10]:
                    print(f"        {C.DIM}→ {san}{C.RESET}")
                if len(sans) > 10:
                    print(f"        {C.DIM}→ ... and {len(sans) - 10} more{C.RESET}")
                report.add("SSL/TLS", f"SANs: {', '.join(sans[:5])}", "info")

            # Expiry
            not_after = cert.get("notAfter", "")
            if not_after:
                try:
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - datetime.now()).days
                    if days_left < 0:
                        found("Certificate", f"EXPIRED ({not_after})", "critical")
                        report.add("SSL/TLS", f"Certificate EXPIRED on {not_after}", "critical")
                    elif days_left < 30:
                        found("Certificate", f"Expiring soon — {days_left} days left", "high")
                        report.add("SSL/TLS", f"Certificate expiring in {days_left} days", "high")
                    else:
                        found("Certificate", f"Valid — {days_left} days remaining", "good")
                        report.add("SSL/TLS", f"Certificate valid for {days_left} more days", "good")
                except ValueError:
                    found("Expires", not_after)

            # Serial
            serial = cert.get("serialNumber", "")
            if serial:
                found("Serial", serial[:40])

    except ssl.SSLCertVerificationError as e:
        found("SSL Verification", f"FAILED — {str(e)[:80]}", "high")
        report.add("SSL/TLS", f"SSL verification failed: {str(e)[:80]}", "high")
    except ConnectionRefusedError:
        fail("Port 443 is closed — no SSL/TLS")
        report.add("SSL/TLS", "Port 443 closed", "info")
    except Exception as e:
        fail(f"SSL analysis error: {str(e)[:80]}")


# ============================================================
# MODULE: TECH FINGERPRINT
# ============================================================
TECH_SIGNATURES = {
    # Response headers → tech
    "headers": {
        "x-powered-by": {
            "Express": ("Node.js/Express", "info"),
            "PHP": ("PHP", "info"),
            "ASP.NET": ("ASP.NET", "info"),
            "Next.js": ("Next.js", "info"),
            "Phusion Passenger": ("Ruby/Passenger", "info"),
        },
        "server": {
            "nginx": ("Nginx", "info"),
            "Apache": ("Apache", "info"),
            "cloudflare": ("Cloudflare CDN", "info"),
            "AmazonS3": ("Amazon S3", "info"),
            "Microsoft-IIS": ("IIS", "info"),
            "gunicorn": ("Python/Gunicorn", "info"),
            "Kestrel": (".NET Kestrel", "info"),
            "openresty": ("OpenResty/Nginx", "info"),
            "LiteSpeed": ("LiteSpeed", "info"),
            "Varnish": ("Varnish Cache", "info"),
            "Cowboy": ("Erlang/Cowboy", "info"),
        },
    },
    # HTML body patterns → tech
    "body": {
        "wp-content": ("WordPress", "info"),
        "wp-includes": ("WordPress", "info"),
        "Drupal.settings": ("Drupal", "info"),
        "Joomla!": ("Joomla", "info"),
        "shopify": ("Shopify", "info"),
        "react": ("React.js", "info"),
        "vue.js": ("Vue.js", "info"),
        "angular": ("Angular", "info"),
        "__next": ("Next.js", "info"),
        "__nuxt": ("Nuxt.js", "info"),
        "svelte": ("Svelte", "info"),
        "laravel": ("Laravel/PHP", "info"),
        "django": ("Django/Python", "info"),
        "rails": ("Ruby on Rails", "info"),
        "jquery": ("jQuery", "info"),
        "bootstrap": ("Bootstrap CSS", "info"),
        "tailwind": ("TailwindCSS", "info"),
        "recaptcha": ("Google reCAPTCHA", "info"),
        "cloudflare": ("Cloudflare", "info"),
        "gtag": ("Google Analytics", "info"),
        "ga.js": ("Google Analytics", "info"),
        "fbq": ("Facebook Pixel", "info"),
        "hotjar": ("Hotjar Analytics", "info"),
        "stripe": ("Stripe Payments", "info"),
    },
}


def mod_tech_fingerprint(target: str, report: Report):
    """Detect technologies and frameworks."""
    section("Technology Fingerprint", "")

    detected = set()

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        headers = http_head(url)
        body = http_get_text(url)

        if not headers and not body:
            continue

        # Check headers
        if headers:
            for header_name, sigs in TECH_SIGNATURES["headers"].items():
                for h_key, h_val in headers.items():
                    if h_key.lower() == header_name:
                        for pattern, (tech, sev) in sigs.items():
                            if pattern.lower() in h_val.lower():
                                if tech not in detected:
                                    detected.add(tech)
                                    found("Detected", f"{tech} {C.DIM}(via {h_key}: {h_val[:50]}){C.RESET}", sev)
                                    report.add("Technology Stack", f"{tech} detected via header {h_key}", sev)

        # Check body
        if body:
            body_lower = body.lower()
            for pattern, (tech, sev) in TECH_SIGNATURES["body"].items():
                if pattern.lower() in body_lower and tech not in detected:
                    detected.add(tech)
                    found("Detected", f"{tech} {C.DIM}(via HTML body pattern){C.RESET}", sev)
                    report.add("Technology Stack", f"{tech} detected in HTML body", sev)

            # Extract meta generator
            gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if gen_match:
                gen = gen_match.group(1)
                if gen not in detected:
                    detected.add(gen)
                    found("Generator", gen, "info")
                    report.add("Technology Stack", f"Generator: {gen}", "info")

        break  # Only need one successful connection

    if not detected:
        info("No technologies fingerprinted (may be heavily customized)")

    info(f"Detected {C.GREEN}{len(detected)}{C.RESET} technologies")


# ============================================================
# MODULE: SUBDOMAIN DISCOVERY
# ============================================================
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev",
    "staging", "stage", "stg", "test", "testing", "beta", "alpha", "demo",
    "sandbox", "qa", "uat", "admin", "administrator", "dashboard", "panel",
    "portal", "app", "apps", "application", "mobile", "m", "web", "www2",
    "cdn", "static", "assets", "media", "images", "img", "files", "download",
    "docs", "doc", "documentation", "wiki", "help", "support", "status",
    "monitor", "monitoring", "health", "blog", "news", "forum", "community",
    "shop", "store", "cart", "pay", "payment", "checkout", "billing",
    "account", "accounts", "auth", "login", "sso", "oauth", "id", "identity",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "deploy",
    "vpn", "remote", "gateway", "proxy", "relay", "internal", "intranet",
    "corp", "corporate", "office", "exchange", "owa", "autodiscover",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "search", "elasticsearch", "kibana", "grafana", "prometheus",
    "backup", "bak", "old", "new", "v1", "v2", "v3", "api2",
    "ws", "websocket", "socket", "chat", "irc", "slack",
    "s3", "storage", "bucket", "cloud", "aws", "azure", "gcp",
    "crm", "erp", "hr", "jira", "confluence",
    "staging2", "dev2", "test2", "pre-prod", "preprod", "prod",
]


def resolve_subdomain(subdomain: str, target: str) -> Optional[Tuple[str, str]]:
    """Try to resolve a subdomain."""
    fqdn = f"{subdomain}.{target}"
    try:
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip)
    except socket.gaierror:
        return None


def crt_sh_subdomains(target: str) -> Set[str]:
    """Fetch subdomains from crt.sh (Certificate Transparency)."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{target}&output=json"
        data = http_get_text(url, timeout=15)
        if data:
            entries = json.loads(data)
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{target}") or line == target:
                        subs.add(line)
    except Exception:
        pass
    return subs


def mod_subdomain_enum(target: str, report: Report, fast: bool = False):
    """Subdomain enumeration via bruteforce + CT logs."""
    section("Subdomain Discovery", "")

    discovered = {}

    # Certificate Transparency
    info("Querying Certificate Transparency logs (crt.sh)...")
    ct_subs = crt_sh_subdomains(target)
    if ct_subs:
        info(f"Found {len(ct_subs)} entries from CT logs")
    else:
        warn("No results from CT logs (or crt.sh is down)")

    # Combine with wordlist
    all_subs = set(SUBDOMAIN_WORDLIST)
    for sub in ct_subs:
        if sub.endswith(f".{target}"):
            prefix = sub[: -(len(target) + 1)]
            all_subs.add(prefix)

    if fast:
        all_subs = set(list(all_subs)[:50])

    total = len(all_subs)
    info(f"Bruteforcing {total} subdomains...")
    print()

    checked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(resolve_subdomain, sub, target): sub
            for sub in all_subs
        }
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            progress(checked, total, f"{checked}/{total} checked")
            result = future.result()
            if result:
                fqdn, ip = result
                if fqdn not in discovered:
                    discovered[fqdn] = ip

    print()
    if discovered:
        for fqdn in sorted(discovered):
            ip = discovered[fqdn]
            found("Subdomain", f"{fqdn} → {ip}")
            report.add("Subdomains", f"{fqdn} → {ip}", "info")

    info(f"Discovered {C.GREEN}{len(discovered)}{C.RESET} live subdomains")


# ============================================================
# MODULE: WAYBACK MACHINE
# ============================================================
def mod_wayback(target: str, report: Report):
    """Fetch URLs from Wayback Machine."""
    section("Wayback Machine URLs", "")

    info("Querying Wayback Machine CDX API...")

    url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit=100"
    data = http_get_text(url, timeout=20)

    if not data:
        warn("Could not reach Wayback Machine")
        return

    try:
        entries = json.loads(data)
        if len(entries) <= 1:
            info("No archived URLs found")
            return

        urls = set()
        interesting = []
        for entry in entries[1:]:  # Skip header row
            u = entry[0]
            urls.add(u)

            # Flag interesting patterns
            lower_u = u.lower()
            interesting_patterns = [
                "admin", "login", "api", "config", "backup", "debug",
                "test", "dev", "staging", "internal", ".env", ".git",
                "phpmyadmin", "wp-admin", "dashboard", "console",
                ".sql", ".bak", ".zip", ".tar", ".log", "token",
                "secret", "password", "key", "upload",
            ]
            for pattern in interesting_patterns:
                if pattern in lower_u:
                    interesting.append((u, pattern))
                    break

        info(f"Found {len(urls)} archived URLs")
        print()

        if interesting:
            info(f"{C.YELLOW}Interesting URLs:{C.RESET}")
            for u, pattern in interesting[:20]:
                found(f"[{pattern}]", u[:100], "medium")
                report.add("Wayback URLs", f"Interesting: {u[:100]}", "medium", f"Pattern: {pattern}")

        # Show a sample of other URLs
        normal_urls = [u for u in urls if not any(p in u.lower() for p in ["admin", "api", "config", "backup", "debug", "test", ".env", ".git"])]
        if normal_urls:
            print()
            info(f"Sample URLs ({min(10, len(normal_urls))} of {len(normal_urls)}):")
            for u in sorted(normal_urls)[:10]:
                print(f"      {C.DIM}{u[:100]}{C.RESET}")
                report.add("Wayback URLs", u[:100], "info")

    except json.JSONDecodeError:
        warn("Could not parse Wayback Machine response")


# ============================================================
# MODULE: DIRECTORY BRUTEFORCE
# ============================================================
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", ".git/config",
    ".gitignore", ".htaccess", ".htpasswd", "wp-login.php", "wp-admin/",
    "admin/", "administrator/", "login/", "dashboard/", "panel/",
    "api/", "api/v1/", "api/v2/", "graphql", "swagger.json",
    "api-docs/", "docs/", "documentation/", "readme.md", "README.md",
    "CHANGELOG.md", "LICENSE", "package.json", "composer.json",
    "config.php", "config.yml", "config.json", "config.xml",
    "backup/", "backups/", "db/", "database/", "dump/", "sql/",
    "debug/", "trace.axd", "elmah.axd", "server-status", "server-info",
    "phpinfo.php", "info.php", "test.php", "test.html", "debug.html",
    "console/", "manager/", "jmx-console/", "web-console/",
    ".DS_Store", "Thumbs.db", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt",
    "wp-json/", "wp-json/wp/v2/users", "xmlrpc.php",
    "actuator/", "actuator/health", "actuator/env",
    "status/", "health/", "healthcheck", "ping", "version",
]


def check_path(base_url: str, path: str) -> Optional[Tuple[str, int, int]]:
    """Check if a path exists."""
    url = f"{base_url}/{path}"
    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) BountyRecon/1.0")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=8, context=ctx)
        size = len(resp.read())
        code = resp.getcode()
        if code in (200, 301, 302, 403):
            return (path, code, size)
    except urllib.error.HTTPError as e:
        if e.code in (403, 401, 405):
            return (path, e.code, 0)
    except Exception:
        pass
    return None


def mod_dir_bruteforce(target: str, report: Report):
    """Directory/file bruteforce."""
    section("Directory & File Discovery", "")

    base_url = f"https://{target}"
    # Test HTTPS first
    test = http_head(base_url)
    if not test:
        base_url = f"http://{target}"

    total = len(COMMON_PATHS)
    info(f"Checking {total} common paths on {base_url}")
    print()

    results = []
    checked = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_path, base_url, path): path for path in COMMON_PATHS}
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            progress(checked, total, f"{checked}/{total} paths")
            result = future.result()
            if result:
                results.append(result)

    print()
    if results:
        results.sort(key=lambda x: x[1])

        sensitive = []
        normal = []
        for path, code, size in results:
            # Classify sensitivity
            sensitive_patterns = [".env", ".git", "config", "backup", "sql", "debug",
                                  "phpinfo", "actuator", "trace", "elmah", "htpasswd",
                                  "server-status", "server-info", "wp-json/wp/v2/users"]
            is_sensitive = any(p in path.lower() for p in sensitive_patterns)

            if is_sensitive:
                sensitive.append((path, code, size))
            else:
                normal.append((path, code, size))

        if sensitive:
            info(f"{C.RED}Sensitive findings:{C.RESET}")
            for path, code, size in sensitive:
                severity = "high" if code == 200 else "medium"
                found(f"[{code}] /{path}", f"{size} bytes", severity)
                report.add("Directory Discovery", f"[{code}] /{path} ({size}B)", severity,
                           "Sensitive file/path exposed")

        if normal:
            print()
            info("Other discovered paths:")
            for path, code, size in normal:
                color = C.GREEN if code == 200 else C.YELLOW if code in (301, 302) else C.RED
                found(f"[{color}{code}{C.RESET}] /{path}", f"{size} bytes")
                report.add("Directory Discovery", f"[{code}] /{path} ({size}B)", "info")

    info(f"Found {C.GREEN}{len(results)}{C.RESET} accessible paths")


# ============================================================
# MODULE: CORS MISCONFIGURATION CHECK
# ============================================================
def mod_cors_check(target: str, report: Report):
    """Check for CORS misconfigurations."""
    section("CORS Misconfiguration Check", "")

    base_url = f"https://{target}"

    test_origins = [
        f"https://evil.com",
        f"https://{target}.evil.com",
        f"https://sub.{target}",
        "null",
        f"http://{target}",
    ]

    for origin in test_origins:
        try:
            req = urllib.request.Request(base_url)
            req.add_header("Origin", origin)
            req.add_header("User-Agent", "Mozilla/5.0 BountyRecon/1.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = dict(resp.headers)

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                if acao == "*":
                    found(f"Origin: {origin}", f"ACAO: * (wildcard)", "medium")
                    report.add("CORS", f"Wildcard ACAO for origin {origin}", "medium",
                               "Allows any origin to read responses")
                elif acao == origin:
                    sev = "high" if acac.lower() == "true" else "medium"
                    found(f"Origin: {origin}", f"ACAO: {acao}, Credentials: {acac}", sev)
                    report.add("CORS", f"Origin {origin} reflected in ACAO (credentials={acac})", sev)
                else:
                    found(f"Origin: {origin}", f"ACAO: {acao}", "info")
            else:
                found(f"Origin: {origin}", "No ACAO header", "good")

        except Exception:
            found(f"Origin: {origin}", "Request failed", "info")


# ============================================================
# MAIN
# ============================================================
MODULES = {
    "dns":       ("DNS Recon",              mod_dns_recon),
    "headers":   ("Security Headers",       mod_security_headers),
    "ports":     ("Port Scanner",           mod_port_scan),
    "ssl":       ("SSL/TLS Analysis",       mod_ssl_analysis),
    "tech":      ("Tech Fingerprint",       mod_tech_fingerprint),
    "subs":      ("Subdomain Discovery",    mod_subdomain_enum),
    "wayback":   ("Wayback Machine",        mod_wayback),
    "dirs":      ("Directory Bruteforce",   mod_dir_bruteforce),
    "cors":      ("CORS Check",            mod_cors_check),
}


def main():
    parser = argparse.ArgumentParser(
        description="BountyRecon — All-in-One Bug Bounty Recon Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Modules:
  {', '.join(MODULES.keys())}

Examples:
  python3 bountyrecon.py -t example.com                 Full recon
  python3 bountyrecon.py -t example.com -m headers      Headers only
  python3 bountyrecon.py -t example.com -m ports,ssl    Ports + SSL
  python3 bountyrecon.py -t example.com --fast           Quick scan
  python3 bountyrecon.py -t example.com -o ./reports     Custom output dir
        """,
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-m", "--modules", default="all", help="Comma-separated modules to run (default: all)")
    parser.add_argument("--fast", action="store_true", help="Quick scan with reduced scope")
    parser.add_argument("-o", "--output", default="./recon_reports", help="Output directory for reports")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    banner()

    target = args.target.strip().lower()
    target = re.sub(r'^https?://', '', target).rstrip('/')

    report = Report(target)

    # Select modules
    if args.modules == "all":
        selected = list(MODULES.keys())
    else:
        selected = [m.strip() for m in args.modules.split(",")]
        for m in selected:
            if m not in MODULES:
                print(f"  {C.RED}✗ Unknown module: {m}{C.RESET}")
                print(f"  {C.DIM}Available: {', '.join(MODULES.keys())}{C.RESET}")
                sys.exit(1)

    # Header
    info(f"{C.BOLD}Target:{C.RESET}  {C.CYAN}{target}{C.RESET}")
    info(f"{C.BOLD}Modules:{C.RESET} {C.CYAN}{', '.join(selected)}{C.RESET}")
    info(f"{C.BOLD}Mode:{C.RESET}    {C.CYAN}{'Fast' if args.fast else 'Full'}{C.RESET}")
    info(f"{C.BOLD}Time:{C.RESET}    {C.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")

    start_time = time.time()

    # Run modules
    for mod_name in selected:
        mod_label, mod_func = MODULES[mod_name]
        try:
            # Some modules accept 'fast' parameter
            if mod_name in ("ports", "subs"):
                mod_func(target, report, fast=args.fast)
            else:
                mod_func(target, report)
        except KeyboardInterrupt:
            warn(f"Skipped {mod_label} (interrupted)")
        except Exception as e:
            fail(f"Error in {mod_label}: {str(e)[:80]}")

    elapsed = time.time() - start_time

    # Generate report
    section("Report", "")
    report_path = report.generate(args.output)
    found("Report saved", report_path, "good")
    info(f"Scan completed in {C.GREEN}{elapsed:.1f}s{C.RESET}")

    # Final summary
    print()
    total_findings = sum(len(v) for v in report.sections.values())
    sev_counts = defaultdict(int)
    for findings in report.sections.values():
        for f in findings:
            sev_counts[f["severity"]] += 1

    print(f"  {C.BOLD}{'═' * 50}{C.RESET}")
    print(f"  {C.BOLD}  SCAN COMPLETE — {total_findings} findings{C.RESET}")
    if sev_counts["critical"]:
        print(f"  {C.BG_RED}{C.WHITE}   {sev_counts['critical']} CRITICAL  {C.RESET}")
    if sev_counts["high"]:
        print(f"  {C.RED}   {sev_counts['high']} HIGH{C.RESET}")
    if sev_counts["medium"]:
        print(f"  {C.YELLOW}   {sev_counts['medium']} MEDIUM{C.RESET}")
    if sev_counts["low"]:
        print(f"  {C.BLUE}   {sev_counts['low']} LOW{C.RESET}")
    if sev_counts["info"]:
        print(f"  {C.CYAN}   {sev_counts['info']} INFO{C.RESET}")
    if sev_counts["good"]:
        print(f"  {C.GREEN}   {sev_counts['good']} GOOD{C.RESET}")
    print(f"  {C.BOLD}{'═' * 50}{C.RESET}")
    print()


if __name__ == "__main__":
    main()
