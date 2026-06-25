#!/usr/bin/env python3
"""
CORTEX_OSINT - Multi-Tool OSINT Framework
Authorized use only. Pre-authorization is verified.
Made by: Germanex3000
"""

import argparse
import sys
import json
import csv
import re
import time
import socket
import ssl
import os
import ipaddress
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple, Any

# Optional imports with fallback
try:
    import requests
    from bs4 import BeautifulSoup
    REQUESTS_BS4 = True
except ImportError:
    REQUESTS_BS4 = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    DNS_PYTHON = True
except ImportError:
    DNS_PYTHON = False

try:
    import whois
    WHOIS_AVAIL = True
except ImportError:
    WHOIS_AVAIL = False

VERSION = "3.5.0"
BANNER = f"""
╔══════════════════════════════════════════╗
║         CORTEX_OSINT V3.5                ║
║     Multi-Tool OSINT Framework           ║
║     Authorized Security Testing Only     ║
╚══════════════════════════════════════════╝
"""


class Color:
    """Terminal colors"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def cprint(text: str, color: str = "", bold: bool = False):
    """Color print wrapper"""
    if bold:
        print(f"{Color.BOLD}{color}{text}{Color.RESET}")
    else:
        print(f"{color}{text}{Color.RESET}")


# ─────────────────────────────────────────────
# MODULE 1: DNS Enumeration
# ─────────────────────────────────────────────
class DNSEnumerator:
    def __init__(self, domain: str, threads: int = 10):
        self.domain = domain.rstrip('.')
        self.threads = threads
        self.results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "soa_records": [],
            "srv_records": [],
            "zone_transfer": None,
            "subdomains": []
        }
        # Common subdomain wordlist (abbreviated — expand in production)
        self.sub_wordlist = [
            "www", "mail", "ftp", "admin", "blog", "webmail", "vpn", "api",
            "dev", "staging", "test", "demo", "beta", "app", "cdn", "m",
            "mobile", "shop", "store", "portal", "secure", "smtp", "pop3",
            "imap", "remote", "support", "help", "forum", "wiki", "docs",
            "status", "git", "jenkins", "jira", "confluence", "svn",
            "backup", "ns1", "ns2", "mx1", "mx2", "cpanel", "whm",
            "autodiscover", "owa", "exchange", "direct", "files", "upload",
            "download", "cloud", "s3", "assets", "static", "img", "css",
            "js", "proxy", "gateway", "router", "firewall", "monitor",
            "logs", "db", "database", "mysql", "redis", "proxy", "intranet",
            "dashboard", "analytics", "tracking", "metrics", "stats"
        ]

    def query_a(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            self.results["a_records"] = [str(r) for r in answers]
        except Exception:
            pass

    def query_aaaa(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'AAAA')
            self.results["aaaa_records"] = [str(r) for r in answers]
        except Exception:
            pass

    def query_mx(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            for r in answers:
                self.results["mx_records"].append({
                    "preference": r.preference,
                    "exchange": str(r.exchange)
                })
        except Exception:
            pass

    def query_ns(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'NS')
            self.results["ns_records"] = [str(r) for r in answers]
        except Exception:
            pass

    def query_txt(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            self.results["txt_records"] = [str(r) for r in answers]
        except Exception:
            pass

    def query_cname(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'CNAME')
            self.results["cname_records"] = [str(r) for r in answers]
        except Exception:
            pass

    def query_soa(self):
        if not DNS_PYTHON:
            return
        try:
            answers = dns.resolver.resolve(self.domain, 'SOA')
            for r in answers:
                self.results["soa_records"] = {
                    "mname": str(r.mname),
                    "rname": str(r.rname),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
        except Exception:
            pass

    def query_srv(self):
        if not DNS_PYTHON:
            return
        srv_services = ["_sip._tcp", "_sip._udp", "_xmpp._tcp", "_ldap._tcp",
                        "_kerberos._tcp", "_imap._tcp", "_pop3._tcp"]
        for service in srv_services:
            try:
                answers = dns.resolver.resolve(f"{service}.{self.domain}", 'SRV')
                for r in answers:
                    self.results["srv_records"].append({
                        "service": service,
                        "target": str(r.target),
                        "port": r.port,
                        "priority": r.priority,
                        "weight": r.weight
                    })
            except Exception:
                pass

    def attempt_zone_transfer(self):
        """Attempt DNS zone transfer from each NS"""
        if not DNS_PYTHON:
            return
        for ns in self.results.get("ns_records", []):
            try:
                ns_ip = str(dns.resolver.resolve(ns, 'A')[0])
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain))
                self.results["zone_transfer"] = []
                for name, node in zone.nodes.items():
                    self.results["zone_transfer"].append(str(name))
                cprint(f"[+] Zone transfer succeeded from {ns}!", Color.GREEN)
                break
            except Exception:
                continue

    def brute_subdomains(self):
        """Brute force subdomains using wordlist"""
        if not DNS_PYTHON:
            return
        found = []
        def check_sub(sub):
            target = f"{sub}.{self.domain}"
            try:
                dns.resolver.resolve(target, 'A')
                return target
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                return None
            except Exception:
                return None

        cprint(f"[*] Brute-forcing {len(self.sub_wordlist)} subdomains...", Color.YELLOW)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_sub, sub): sub for sub in self.sub_wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    cprint(f"    [+] Found: {result}", Color.GREEN)

        self.results["subdomains"] = sorted(found)

    def enumerate_all(self):
        cprint(f"\n{Color.BOLD}[ DNS Enumeration: {self.domain} ]{Color.RESET}", Color.CYAN)
        self.query_a()
        self.query_aaaa()
        self.query_mx()
        self.query_ns()
        self.query_txt()
        self.query_cname()
        self.query_soa()
        self.query_srv()

        if self.results["a_records"]:
            cprint(f"  A Records: {', '.join(self.results['a_records'])}", Color.GREEN)
        if self.results["aaaa_records"]:
            cprint(f"  AAAA Records: {', '.join(self.results['aaaa_records'])}", Color.GREEN)
        if self.results["mx_records"]:
            for mx in self.results["mx_records"]:
                cprint(f"  MX: [{mx['preference']}] {mx['exchange']}", Color.GREEN)
        if self.results["ns_records"]:
            cprint(f"  NS Records: {', '.join(self.results['ns_records'])}", Color.GREEN)
        if self.results["txt_records"]:
            cprint(f"  TXT Records:", Color.GREEN)
            for txt in self.results["txt_records"]:
                cprint(f"    {txt}", Color.GREEN)
        if self.results["soa_records"]:
            soa = self.results["soa_records"]
            cprint(f"  SOA: {soa['mname']} ({soa['rname']}) serial={soa['serial']}", Color.GREEN)

        return self.results


# ─────────────────────────────────────────────
# MODULE 2: WHOIS Lookup
# ─────────────────────────────────────────────
class WhoisLookup:
    @staticmethod
    def lookup(target: str) -> Dict:
        if not WHOIS_AVAIL:
            return {"error": "python-whois not installed. pip install python-whois"}
        try:
            w = whois.whois(target)
            result = {
                "domain": w.get("domain_name"),
                "registrar": w.get("registrar"),
                "creation_date": str(w.get("creation_date")),
                "expiration_date": str(w.get("expiration_date")),
                "updated_date": str(w.get("updated_date")),
                "name_servers": w.get("name_servers"),
                "org": w.get("org"),
                "country": w.get("country"),
                "state": w.get("state"),
                "city": w.get("city"),
                "address": w.get("address"),
                "emails": w.get("emails"),
                "status": w.get("status")
            }
            return result
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def print_lookup(target: str):
        cprint(f"\n{Color.BOLD}[ WHOIS Lookup: {target} ]{Color.RESET}", Color.CYAN)
        result = WhoisLookup.lookup(target)
        if "error" in result:
            cprint(f"  Error: {result['error']}", Color.RED)
            return
        for key, value in result.items():
            if value and value != "None" and value != [""]:
                if isinstance(value, list):
                    cprint(f"  {key.replace('_', ' ').title()}: {', '.join(str(v) for v in value if v)}", Color.GREEN)
                else:
                    cprint(f"  {key.replace('_', ' ').title()}: {value}", Color.GREEN)


# ─────────────────────────────────────────────
# MODULE 3: HTTP Reconnaissance
# ─────────────────────────────────────────────
class HTTPRecon:
    def __init__(self, url: str, timeout: int = 10):
        self.raw_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.timeout = timeout
        self.results = {}

    def fetch_headers(self):
        if not REQUESTS_BS4:
            return {"error": "requests/bs4 not installed"}
        try:
            resp = requests.get(self.url, timeout=self.timeout, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; HackerOSINT/2.0)"})
            self.results["status_code"] = resp.status_code
            self.results["final_url"] = resp.url
            self.results["headers"] = dict(resp.headers)
            self.results["cookies"] = dict(resp.cookies)
            self.results["text_length"] = len(resp.text)
            return resp
        except requests.exceptions.RequestException as e:
            self.results["error"] = str(e)
            return None

    def analyze_headers(self):
        headers = self.results.get("headers", {})
        findings = []

        # Security header checks
        checks = {
            "Strict-Transport-Security": "HSTS not enabled",
            "Content-Security-Policy": "CSP missing",
            "X-Content-Type-Options": "X-Content-Type-Options missing",
            "X-Frame-Options": "Clickjacking protection missing",
            "X-XSS-Protection": "XSS filter missing",
            "Referrer-Policy": "Referrer-Policy missing",
            "Permissions-Policy": "Permissions-Policy missing",
            "Set-Cookie": None  # handled separately
        }

        for header, warning in checks.items():
            if header not in headers:
                if warning:
                    findings.append({"severity": "info", "finding": warning})

        # Server info leak
        if "Server" in headers:
            findings.append({"severity": "low", "finding": f"Server header leaks: {headers['Server']}"})
        if "X-Powered-By" in headers:
            findings.append({"severity": "low", "finding": f"X-Powered-By leaks: {headers['X-Powered-By']}"})

        # Cookies without security flags
        if "Set-Cookie" in headers:
            cookie_val = headers.get("Set-Cookie", "")
            if "HttpOnly" not in cookie_val:
                findings.append({"severity": "medium", "finding": "Cookie missing HttpOnly flag"})
            if "Secure" not in cookie_val and self.url.startswith("https"):
                findings.append({"severity": "medium", "finding": "Cookie missing Secure flag on HTTPS"})
            if "SameSite" not in cookie_val:
                findings.append({"severity": "low", "finding": "Cookie missing SameSite attribute"})

        self.results["security_findings"] = findings
        return findings

    def extract_links(self, html_content: str) -> List[str]:
        if not REQUESTS_BS4:
            return []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            links = set()
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
                for attr in ['href', 'src', 'action']:
                    val = tag.get(attr)
                    if val:
                        absolute = urljoin(self.url, val)
                        links.add(absolute)
            return sorted(links)
        except Exception:
            return []

    def extract_emails(self, text: str) -> List[str]:
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))

    def extract_js_endpoints(self, text: str) -> List[str]:
        """Extract potential API endpoints from JS-like patterns"""
        patterns = [
            r'["\']/(?:api|v[0-9]+|rest|graphql)/[^"\'\s]*["\']',
            r'["\']https?://[^"\'\s]*["\']',
        ]
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for m in matches:
                endpoints.add(m.strip('"\''))
        return sorted(endpoints)

    def run(self):
        cprint(f"\n{Color.BOLD}[ HTTP Reconnaissance: {self.url} ]{Color.RESET}", Color.CYAN)
        resp = self.fetch_headers()
        if resp is None:
            cprint(f"  Error: {self.results.get('error', 'Connection failed')}", Color.RED)
            return self.results

        cprint(f"  Status: {resp.status_code}", Color.GREEN)
        cprint(f"  Final URL: {resp.url}", Color.GREEN)

        self.analyze_headers()
        if self.results.get("security_findings"):
            cprint(f"\n  {Color.BOLD}Security Findings:{Color.RESET}", Color.YELLOW)
            for f in self.results["security_findings"]:
                color = Color.YELLOW if f["severity"] == "info" else Color.RED if f["severity"] == "medium" else Color.MAGENTA
                cprint(f"    [{f['severity'].upper()}] {f['finding']}", color)

        # Extract links, emails, endpoints
        if resp.text:
            links = self.extract_links(resp.text)
            if links:
                cprint(f"\n  Internal Links ({len(links)} found):", Color.CYAN)
                for link in links[:20]:  # show first 20
                    if self.domain in link:
                        cprint(f"    {link}", Color.GREEN)
                if len(links) > 20:
                    cprint(f"    ... and {len(links)-20} more", Color.YELLOW)

            self.results["emails"] = self.extract_emails(resp.text)
            if self.results["emails"]:
                cprint(f"\n  Emails Found:", Color.MAGENTA)
                for email in self.results["emails"]:
                    cprint(f"    {email}", Color.MAGENTA)

            self.results["js_endpoints"] = self.extract_js_endpoints(resp.text)
            if self.results["js_endpoints"]:
                cprint(f"\n  Potential API Endpoints:", Color.CYAN)
                for ep in self.results["js_endpoints"][:15]:
                    cprint(f"    {ep}", Color.CYAN)

        return self.results


# ─────────────────────────────────────────────
# MODULE 4: Certificate Transparency (crt.sh)
# ─────────────────────────────────────────────
class CertTransparency:
    def __init__(self, domain: str):
        self.domain = domain

    def query_crtsh(self) -> List[Dict]:
        """Query crt.sh for certificate transparency logs"""
        if not REQUESTS_BS4:
            return []
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = requests.get(url, timeout=15,
                                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return []
            return []
        except Exception:
            return []

    def extract_subdomains(self, entries: List[Dict]) -> List[str]:
        subdomains = set()
        for entry in entries:
            name = entry.get("name_value", "")
            if name:
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(self.domain) and n != self.domain:
                        # Remove wildcard prefix
                        if n.startswith("*."):
                            n = n[2:]
                        subdomains.add(n)
        return sorted(subdomains)

    def run(self):
        cprint(f"\n{Color.BOLD}[ Certificate Transparency: {self.domain} ]{Color.RESET}", Color.CYAN)
        entries = self.query_crtsh()
        if not entries:
            cprint("  No entries found or query failed", Color.YELLOW)
            return []

        subdomains = self.extract_subdomains(entries)
        cprint(f"  Found {len(subdomains)} unique subdomains via CRT:", Color.GREEN)
        for sub in subdomains[:30]:
            cprint(f"    {sub}", Color.GREEN)
        if len(subdomains) > 30:
            cprint(f"    ... and {len(subdomains)-30} more", Color.YELLOW)

        return subdomains


# ─────────────────────────────────────────────
# MODULE 5: Port Scanner (Basic TCP)
# ─────────────────────────────────────────────
class PortScanner:
    def __init__(self, target: str, ports: List[int] = None, threads: int = 50, timeout: float = 1.0):
        self.target = target
        if ports:
            self.ports = ports
        else:
            self.ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                          993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                          8080, 8443, 9090, 27017]
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []

    def scan_port(self, port: int) -> Optional[int]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    service = "unknown"
                return (port, service)
            return None
        except Exception:
            return None

    def run(self):
        cprint(f"\n{Color.BOLD}[ Port Scanner: {self.target} ]{Color.RESET}", Color.CYAN)
        cprint(f"  Scanning {len(self.ports)} ports...", Color.YELLOW)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service = result
                    self.open_ports.append(result)
                    cprint(f"    OPEN: {port}/{service.upper()}", Color.GREEN)

        if not self.open_ports:
            cprint("  No open ports found among scanned range", Color.YELLOW)
        else:
            self.open_ports.sort(key=lambda x: x[0])

        return self.open_ports


# ─────────────────────────────────────────────
# MODULE 6: Directory Fuzzer
# ─────────────────────────────────────────────
class DirFuzzer:
    def __init__(self, base_url: str, wordlist: List[str] = None, threads: int = 10):
        self.base_url = base_url.rstrip('/')
        if wordlist:
            self.wordlist = wordlist
        else:
            self.wordlist = [
                "admin", "login", "wp-admin", "administrator", "backup", ".git",
                ".env", "config", "robots.txt", "sitemap.xml", ".htaccess",
                "api", "v1", "v2", "graphql", "swagger", "docs", "phpmyadmin",
                "uploads", "files", "assets", "private", "secret", "test",
                "dev", "console", "dashboard", "panel", "cpanel", "manager",
                "status", "health", "metrics", "prometheus", "jenkins",
                ".well-known", "security.txt", "crossdomain.xml", "clientaccesspolicy.xml"
            ]
        self.threads = threads
        self.found = []

    def check_path(self, path: str) -> Optional[Dict]:
        if not REQUESTS_BS4:
            return None
        url = f"{self.base_url}/{path}"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code in [200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 500]:
                size = len(resp.content)
                return {
                    "path": path,
                    "url": url,
                    "status": resp.status_code,
                    "size": size
                }
            return None
        except Exception:
            return None

    def run(self):
        cprint(f"\n{Color.BOLD}[ Directory Fuzzing: {self.base_url} ]{Color.RESET}", Color.CYAN)
        cprint(f"  Testing {len(self.wordlist)} paths...", Color.YELLOW)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_path, p): p for p in self.wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.found.append(result)
                    status = result["status"]
                    color = Color.GREEN if status < 400 else Color.YELLOW if status < 500 else Color.RED
                    cprint(f"    [{status}] /{result['path']} ({result['size']} bytes)", color)

        if not self.found:
            cprint("  No interesting paths found", Color.YELLOW)

        return self.found


# ─────────────────────────────────────────────
# MODULE 7: IP Geolocation & Reputation
# ─────────────────────────────────────────────
class IPIntel:
    @staticmethod
    def resolve_domain(domain: str) -> List[str]:
        """Resolve domain to IPs"""
        ips = []
        try:
            for info in socket.getaddrinfo(domain, 80):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception:
            pass
        return ips

    @staticmethod
    def get_ip_info(ip: str) -> Dict:
        """Get basic IP info"""
        info = {"ip": ip}
        try:
            # Reverse DNS
            hostname, _, _ = socket.gethostbyaddr(ip)
            info["hostname"] = hostname
        except Exception:
            info["hostname"] = None

        # ASN via whois
        if WHOIS_AVAIL:
            try:
                w = whois.whois(ip)
                info["org"] = w.get("org")
                info["country"] = w.get("country")
            except Exception:
                pass

        return info

    @staticmethod
    def run(target: str):
        cprint(f"\n{Color.BOLD}[ IP Intelligence: {target} ]{Color.RESET}", Color.CYAN)

        # Check if it's already an IP
        try:
            ipaddress.ip_address(target)
            ips = [target]
        except ValueError:
            ips = IPIntel.resolve_domain(target)

        if not ips:
            cprint("  Could not resolve target", Color.RED)
            return

        for ip in ips:
            cprint(f"\n  Target IP: {ip}", Color.CYAN)
            info = IPIntel.get_ip_info(ip)
            if info.get("hostname"):
                cprint(f"  Hostname: {info['hostname']}", Color.GREEN)
            if info.get("org"):
                cprint(f"  Organization: {info['org']}", Color.GREEN)
            if info.get("country"):
                cprint(f"  Country: {info['country']}", Color.GREEN)


# ─────────────────────────────────────────────
# OUTPUT / REPORTING
# ─────────────────────────────────────────────
class ReportWriter:
    def __init__(self, target: str, output_dir: str = "./osint_output"):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir
        self.data = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "tool_version": VERSION,
            "modules": {}
        }

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def add_module_data(self, module_name: str, data: Any):
        self.data["modules"][module_name] = data

    def save_json(self):
        filename = f"{self.output_dir}/{self.target.replace('.', '_')}_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)
        cprint(f"\n[+] JSON report saved: {filename}", Color.CYAN)
        return filename

    def save_csv(self, module_name: str, data: List[Dict], fieldnames: List[str]):
        if not data:
            return
        filename = f"{self.output_dir}/{self.target.replace('.', '_')}_{module_name}_{self.timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            # Convert non-dict to dict
            for item in data:
                if isinstance(item, dict):
                    writer.writerow(item)
                elif isinstance(item, (list, tuple)):
                    row = {fieldnames[i]: item[i] if i < len(item) else "" for i in range(len(fieldnames))}
                    writer.writerow(row)
                else:
                    writer.writerow({fieldnames[0]: item})
        cprint(f"[+] CSV report saved: {filename}", Color.CYAN)


# ─────────────────────────────────────────────
# MAIN CLI
# ─────────────────────────────────────────────
def full_recon(target: str, output_dir: str = "./osint_output", threads: int = 10):
    """Run all OSINT modules against a target"""
    cprint(BANNER, Color.CYAN, bold=True)
    cprint(f"[*] Target: {target}", Color.BLUE)
    cprint(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Color.BLUE)
    print("=" * 50)

    report = ReportWriter(target, output_dir)

    # Strip protocol for domain-based modules
    domain = target
    if target.startswith(('http://', 'https://')):
        domain = urlparse(target).netloc

    # 1. WHOIS
    if WHOIS_AVAIL:
        WhoisLookup.print_lookup(domain)
        whois_data = WhoisLookup.lookup(domain)
        report.add_module_data("whois", whois_data)
    else:
        cprint("\n[!] WHOIS module skipped (install python-whois)", Color.YELLOW)

    # 2. DNS Enumeration
    dns_enum = DNSEnumerator(domain, threads=threads)
    dns_results = dns_enum.enumerate_all()
    dns_enum.attempt_zone_transfer()
    dns_enum.brute_subdomains()
    report.add_module_data("dns_enum", dns_results)

    # 3. Certificate Transparency
    ct = CertTransparency(domain)
    ct_subdomains = ct.run()
    report.add_module_data("cert_transparency", ct_subdomains)

    # 4. HTTP Recon
    http_recon = HTTPRecon(target)
    http_results = http_recon.run()
    report.add_module_data("http_recon", http_results)

    # 5. IP Intel
    IPIntel.run(domain)

    # 6. Port Scan (only if hostname resolves)
    try:
        test_ip = socket.gethostbyname(domain)
        scanner = PortScanner(test_ip, threads=min(threads * 2, 100))
        ports = scanner.run()
        report.add_module_data("port_scan", [{"port": p, "service": s} for p, s in ports])
    except socket.gaierror:
        cprint(f"\n[!] Cannot resolve {domain} for port scanning", Color.YELLOW)

    # 7. Directory Fuzzing (only on HTTP(S) targets)
    if target.startswith(('http://', 'https://')):
        fuzzer = DirFuzzer(target, threads=threads)
        dirs = fuzzer.run()
        report.add_module_data("dir_fuzzing", dirs)

    # Save reports
    print("\n" + "=" * 50)
    cprint("[*] Generating Reports...", Color.CYAN)
    report.save_json()
    if dns_results.get("subdomains"):
        report.save_csv("subdomains", dns_results["subdomains"], fieldnames=["subdomain"])

    cprint(f"\n[*] Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Color.GREEN)
    return report


def interactive_menu():
    """Interactive menu mode"""
    cprint(BANNER, Color.CYAN, bold=True)

    modules = {
        "1": ("Full Recon (ALL modules)", full_recon),
    }

    while True:
        print(f"\n{Color.BOLD}Available Modules:{Color.RESET}")
        print("  1. Full Recon (WHOIS, DNS, CRT, HTTP, Ports, DirFuzz)")
        print("  2. DNS Enumeration Only")
        print("  3. WHOIS Lookup Only")
        print("  4. HTTP Reconnaissance Only")
        print("  5. Certificate Transparency Only")
        print("  6. Port Scanner Only")
        print("  7. Directory Fuzzer Only")
        print("  8. IP Intelligence Only")
        print("  0. Exit")

        choice = input(f"\n{Color.BOLD}Select module: {Color.RESET}").strip()
        if choice == "0":
            break

        target = input(f"{Color.BOLD}Enter target (domain or URL): {Color.RESET}").strip()
        if not target:
            continue

        threads = input(f"{Color.BOLD}Thread count [10]: {Color.RESET}").strip()
        threads = int(threads) if threads.isdigit() else 10

        if choice == "1":
            full_recon(target, threads=threads)
        elif choice == "2":
            domain = target.split("//")[-1].split("/")[0]
            DNSEnumerator(domain, threads).enumerate_all()
        elif choice == "3":
            domain = target.split("//")[-1].split("/")[0]
            WhoisLookup.print_lookup(domain)
        elif choice == "4":
            HTTPRecon(target).run()
        elif choice == "5":
            domain = target.split("//")[-1].split("/")[0]
            CertTransparency(domain).run()
        elif choice == "6":
            try:
                ip = socket.gethostbyname(target)
                PortScanner(ip, threads=threads).run()
            except Exception as e:
                cprint(f"Error: {e}", Color.RED)
        elif choice == "7":
            if not target.startswith(('http://', 'https://')):
                target = 'https://' + target
            DirFuzzer(target, threads=threads).run()
        elif choice == "8":
            IPIntel.run(target)
        else:
            cprint("Invalid choice", Color.RED)

        input(f"\n{Color.BOLD}Press Enter to continue...{Color.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="CORTEX_OSINT - Multi-Tool OSINT Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tool.py -t example.com                    # Full recon
  python tool.py -t https://example.com -m http    # HTTP recon only
  python tool.py -t example.com -m dns -o ./reports
  python tool.py -t example.com --no-fuzz --threads 20
  python tool.py --interactive                     # Interactive mode
        """
    )
    parser.add_argument("-t", "--target", help="Target domain or URL")
    parser.add_argument("-m", "--module", choices=["all", "dns", "whois", "http", "crt", "port", "dirfuzz", "ip"],
                        default="all", help="Module to run (default: all)")
    parser.add_argument("-o", "--output", default="./osint_output", help="Output directory")
    parser.add_argument("--threads", type=int, default=10, help="Thread count")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip directory fuzzing")
    parser.add_argument("--interactive", action="store_true", help="Interactive menu mode")
    parser.add_argument("--version", action="store_true", help="Show version")

    args = parser.parse_args()

    if args.version:
        print(f"CORTEX_OSINT v{VERSION}")
        sys.exit(0)

    if args.interactive:
        interactive_menu()
        return

    if not args.target:
        parser.print_help()
        cprint("\n[!] Target is required (use -t) or use --interactive", Color.RED)
        sys.exit(1)

    # Run selected module
    target = args.target
    domain = target.split("//")[-1].split("/")[0]

    if args.module == "whois":
        WhoisLookup.print_lookup(domain)
    elif args.module == "dns":
        DNSEnumerator(domain, args.threads).enumerate_all()
    elif args.module == "http":
        HTTPRecon(target).run()
    elif args.module == "crt":
        CertTransparency(domain).run()
    elif args.module == "port":
        try:
            ip = socket.gethostbyname(domain)
            PortScanner(ip, threads=args.threads).run()
        except Exception as e:
            cprint(f"Error resolving {domain}: {e}", Color.RED)
    elif args.module == "dirfuzz":
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        DirFuzzer(target, threads=args.threads).run()
    elif args.module == "ip":
        IPIntel.run(target)
    else:
        full_recon(target, args.output, args.threads)


if __name__ == "__main__":
    main()
