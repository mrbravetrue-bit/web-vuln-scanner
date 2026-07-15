# Web Vulnerability Scanner

A lightweight web reconnaissance/misconfiguration scanner — checks a target
site's security headers, SSL/TLS certificate health, and commonly exposed
sensitive files (`.env`, `.git/config`, backups, etc.), then exports a
terminal-themed HTML report.

![python](https://img.shields.io/badge/python-3.10+-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)

> ⚠️ **Legal & ethical use only.** Only scan sites you own or have explicit
> written authorization to test. This tool contains no exploit code — it
> only reports the *presence* of misconfigurations, the same way any
> vulnerability scanner's summary report would.

## What it checks

1. **Security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
   Referrer-Policy, Permissions-Policy, and Server banner exposure.
2. **SSL/TLS** — certificate expiry, verification errors, negotiated protocol
   version.
3. **Exposed sensitive files** — probes common paths (`.env`, `.git/HEAD`,
   backup files, `.htpasswd`, cloud credential files, etc.) for public
   accessibility.

## Quick start

```bash
cd src
python3 main.py https://example.com
python3 main.py https://example.com --report   # also generate an HTML report
```

No external dependencies — pure Python standard library (`urllib`, `ssl`,
`socket`).

## Why this project

Demonstrates the recon/enumeration phase of a web app pentest engagement:
translating raw HTTP responses and TLS handshake data into prioritized,
actionable findings — a core skill for both offensive (finding issues) and
defensive (fixing them) security roles.

## Roadmap / ideas for v2

- [ ] Crawl and check multiple pages, not just the root
- [ ] Cookie security flag checks (`Secure`, `HttpOnly`, `SameSite`)
- [ ] CORS misconfiguration detection
- [ ] JSON output mode

## License

MIT
