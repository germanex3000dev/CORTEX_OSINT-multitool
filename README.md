# CORTEX_OSINT

> Multi-Tool OSINT Framework for domain and network reconnaissance.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-3.5.0-red)

```
╔══════════════════════════════════════════╗
║         CORTEX_OSINT V3.5                ║
║     Multi-Tool OSINT Framework           ║
║     Authorized Security Testing Only     ║
╚══════════════════════════════════════════╝
```

Greetings, dear SKIDS! Have fun with this little OSINT Framework!

---

## ⚠️ Legal Disclaimer

CORTEX_OSINT is intended for **authorized security testing and research only**. Only run this tool against targets you own or have explicit written permission to test. Unauthorized use may violate local laws. The author assumes no liability for misuse.

---

## Features

| Module | Description |
|---|---|
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV records + zone transfer attempts + subdomain brute-forcing |
| **WHOIS Lookup** | Registrar, dates, org, contacts, name servers |
| **HTTP Reconnaissance** | Headers, security findings, cookie flags, email extraction, JS endpoint discovery |
| **Certificate Transparency** | Subdomain discovery via crt.sh |
| **Port Scanner** | TCP connect scan across common ports |
| **Directory Fuzzer** | Common path discovery with status code reporting |
| **IP Intelligence** | Reverse DNS, ASN, org, and geolocation info |

---

## Installation

```bash
git clone https://github.com/germanex3000dev/CORTEX_OSINT.git
```

```bash
cd CORTEX_OSINT
```
```bash
pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- See `requirements.txt` for dependencies (`requests`, `beautifulsoup4`, `dnspython`, `python-whois`)

---

## Usage

### Full Recon
```bash
python tool.py -t example.com
```

### Specific Module
```bash
python tool.py -t example.com -m dns
python tool.py -t https://example.com -m http
python tool.py -t example.com -m whois
python tool.py -t example.com -m port
python tool.py -t example.com -m crt
python tool.py -t https://example.com -m dirfuzz
python tool.py -t example.com -m ip
```

### Options
```
-t, --target       Target domain or URL
-m, --module       Module to run: all, dns, whois, http, crt, port, dirfuzz, ip (default: all)
-o, --output       Output directory (default: ./osint_output)
--threads          Thread count (default: 10)
--no-fuzz          Skip directory fuzzing
--interactive      Launch interactive menu
--version          Show version
```

### Interactive Mode
```bash
python tool.py --interactive
```

---

## Output

Results are saved to `./osint_output/` by default:

- **JSON** — full structured report per scan
- **CSV** — subdomains list (when applicable)

---

## Modules In Detail

### DNS Enumeration
Queries all common record types and attempts zone transfers from each discovered nameserver. Brute-forces subdomains using a built-in wordlist via multithreaded DNS resolution.

### HTTP Reconnaissance
Fetches response headers and flags missing security headers (HSTS, CSP, X-Frame-Options, etc.), server information leaks, and insecure cookie attributes. Also extracts emails, links, and JS-embedded API endpoints from page content.

### Certificate Transparency
Queries [crt.sh](https://crt.sh) to enumerate subdomains from public certificate logs — often reveals infrastructure not found via DNS brute-force.

### Port Scanner
Performs a TCP connect scan against a curated list of common service ports. Identifies open ports and maps them to service names.

### Directory Fuzzer
Probes for common paths (admin panels, config files, API endpoints, dev artifacts) and reports HTTP status codes and response sizes.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## Author

**Germanex3000**

---

## License

[MIT](LICENSE)
