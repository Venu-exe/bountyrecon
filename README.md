# 🎯 BountyRecon

**All-in-one bug bounty recon toolkit — zero dependencies, pure Python.**

BountyRecon runs subdomain discovery, port scanning, header/CORS/SSL audits, tech fingerprinting, Wayback Machine harvesting, and directory bruteforcing against a target, then rolls everything into a single H1-ready Markdown report.

```
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
```

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

---

## ✨ Features

| Module | Flag | What it does |
|---|---|---|
| 🌐 DNS Recon | `dns` | A / AAAA records + reverse DNS lookups |
| 🛡️ Security Headers | `headers` | Audits OWASP-recommended headers, flags info-leak headers, checks cookie flags |
| 🔌 Port Scanner | `ports` | Fast threaded TCP scan across common + extended port lists, grabs service banners |
| 🔒 SSL/TLS Analysis | `ssl` | Protocol/cipher check, certificate subject/issuer/SANs, expiry countdown |
| 🔍 Tech Fingerprint | `tech` | Detects frameworks, servers, CDNs, and JS libraries from headers + HTML |
| 🌐 Subdomain Discovery | `subs` | Certificate Transparency (crt.sh) lookup + wordlist bruteforce, resolved concurrently |
| 📜 Wayback URLs | `wayback` | Pulls archived URLs from the Wayback CDX API, flags sensitive-looking paths |
| 📂 Directory Bruteforce | `dirs` | Threaded probing of common sensitive files/paths (`.env`, `.git`, admin panels, etc.) |
| 🔓 CORS Check | `cors` | Tests reflected-origin and wildcard `Access-Control-Allow-Origin` misconfigurations |

Every finding is scored (`critical` / `high` / `medium` / `low` / `info` / `good`) and written to a timestamped Markdown report you can attach directly to a bug bounty submission.

---

## 📦 Installation

No dependencies — just Python 3.8+.

```bash
git clone https://github.com/Venu-exe/bountyrecon.git
cd bountyrecon
python3 bountyrecon.py -h
```

---

## 🚀 Usage

```bash
# Full recon (all modules)
python3 bountyrecon.py -t example.com

# Run a single module
python3 bountyrecon.py -t example.com -m headers

# Run several specific modules
python3 bountyrecon.py -t example.com -m ports,ssl,cors

# Quick/reduced-scope scan
python3 bountyrecon.py -t example.com --fast

# Custom report output directory
python3 bountyrecon.py -t example.com -o ./reports

# Disable colored output (e.g. for CI logs)
python3 bountyrecon.py -t example.com --no-color
```

### CLI options

| Flag | Description |
|---|---|
| `-t`, `--target` | Target domain, e.g. `example.com` (required) |
| `-m`, `--modules` | Comma-separated module list (default: `all`) |
| `--fast` | Reduced scope for a quicker scan |
| `-o`, `--output` | Report output directory (default: `./recon_reports`) |
| `--no-color` | Disable ANSI color output |

---

## 📄 Sample Output

```
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🛡️ Security Headers Audit
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [HIGH] Strict-Transport-Security: MISSING
    ✓ Content-Security-Policy: default-src 'self'
    [MEDIUM] Server (info leak): nginx/1.18.0
    ℹ  Header Score: 62% (5/10 headers present)
```

Each run generates a Markdown report like `recon_reports/recon_example.com_20260730_155141.md`, with a severity-count summary table followed by per-module findings — ready to paste into a HackerOne/Bugcrowd report.

---

## 🧩 How it's built

- **Zero third-party dependencies** — only Python's standard library (`socket`, `ssl`, `urllib`, `concurrent.futures`, `argparse`, etc.), so it runs anywhere Python 3 does.
- **Threaded I/O** — port scanning, subdomain resolution, and directory bruteforcing use `concurrent.futures.ThreadPoolExecutor` to parallelize thousands of network checks.
- **Pluggable module registry** — each recon technique is a self-contained `mod_*(target, report)` function registered in a `MODULES` dict, so adding a new check is a matter of writing one function and one dict entry.
- **Central `Report` collector** — every module calls `report.add(section, finding, severity, detail)`; at the end, `Report.generate()` renders everything into one Markdown file with a severity summary table.
- **No external APIs requiring keys** — uses public endpoints (crt.sh, the Wayback CDX API) so it works out of the box.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only** — targets you own or have explicit written permission to test (e.g. via a bug bounty program's scope). Scanning systems without authorization may be illegal in your jurisdiction. The authors assume no liability for misuse.

---

## 📜 License

MIT
