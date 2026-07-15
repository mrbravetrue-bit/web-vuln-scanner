"""
webscan.py
Lightweight web vulnerability scanner. Checks a target URL for:
  - missing/misconfigured security headers
  - SSL/TLS certificate issues
  - commonly exposed sensitive files (.env, .git/config, backup files, etc.)

⚠️ LEGAL / ETHICAL NOTICE
Only scan sites you own or have explicit written permission to test.
No exploit code — this only checks for the *presence* of misconfigurations,
the same way a scanner's summary report would.
"""
import ssl
import socket
import datetime
import urllib.request
import urllib.error
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS — missing allows protocol downgrade attacks.",
    "Content-Security-Policy": "Missing CSP increases XSS impact risk.",
    "X-Content-Type-Options": "Missing allows MIME-sniffing attacks.",
    "X-Frame-Options": "Missing allows clickjacking via iframe embedding.",
    "Referrer-Policy": "Missing may leak URLs/tokens via the Referer header.",
    "Permissions-Policy": "Missing means browser features aren't explicitly restricted.",
}

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/backup.zip", "/backup.sql", "/config.php.bak", "/.DS_Store",
    "/database.yml", "/id_rsa", "/.aws/credentials", "/docker-compose.yml",
    "/.htpasswd", "/phpinfo.php", "/server-status", "/.well-known/security.txt",
]


def fetch(url, timeout=5):
    req = urllib.request.Request(url, headers={"User-Agent": "webscan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(2048)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""
    except Exception:
        return None, {}, b""


def check_headers(url):
    status, headers, _ = fetch(url)
    findings = []
    if status is None:
        return [{"check": "connectivity", "severity": "INFO", "detail": f"Could not connect to {url}"}]

    for header, note in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({"check": header, "severity": "MEDIUM", "detail": note})

    server = headers.get("Server")
    if server:
        findings.append({
            "check": "Server header",
            "severity": "LOW",
            "detail": f"Server banner exposed: '{server}' — consider suppressing version info.",
        })
    return findings


def check_ssl(host, port=443, timeout=5):
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append({"check": "SSL expiry", "severity": "HIGH",
                                      "detail": f"Certificate expired {abs(days_left)} day(s) ago."})
                elif days_left < 30:
                    findings.append({"check": "SSL expiry", "severity": "MEDIUM",
                                      "detail": f"Certificate expires in {days_left} day(s)."})
                findings.append({"check": "SSL protocol", "severity": "INFO",
                                  "detail": f"Negotiated protocol: {ssock.version()}"})
    except ssl.SSLCertVerificationError as e:
        findings.append({"check": "SSL verification", "severity": "HIGH", "detail": str(e)})
    except Exception as e:
        findings.append({"check": "SSL connection", "severity": "INFO", "detail": f"Could not verify SSL: {e}"})
    return findings


def check_exposed_files(base_url):
    findings = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        status, _, body = fetch(url)
        if status == 200 and body:
            findings.append({
                "check": f"exposed file {path}",
                "severity": "HIGH",
                "detail": f"Publicly accessible: {url} (HTTP 200)",
            })
    return findings


def scan(target_url):
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
    host = parsed.hostname

    results = {
        "target": target_url,
        "scanned_at": datetime.datetime.now().isoformat(),
        "headers": check_headers(f"{parsed.scheme}://{host}"),
        "ssl": check_ssl(host) if parsed.scheme == "https" else [],
        "exposed_files": check_exposed_files(f"{parsed.scheme}://{host}"),
    }
    return results
