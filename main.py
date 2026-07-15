"""
main.py
CLI entry point for the web vulnerability scanner.

⚠️ Only scan sites you own or are explicitly authorized to test.

Usage:
    python3 main.py https://example.com [--report]
"""
import argparse
import sys
import webscan
import report

GREEN = "\033[92m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = rf"""{GREEN}{BOLD}
 __        __   _        __
 \ \      / /__| |__ ___ / _\ ___ __ _ _ __
  \ \ /\ / / _ \ '_ (_-<< (_ / __/ _` | '_ \
   \ V  V /  __/ |_) /__|\__ \(_| (_| | | | |
    \_/\_/ \___|_.__/    |___/\___\__,_|_| |_|
{RESET}{DIM}      web misconfiguration & exposure scanner{RESET}
"""

SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": DIM, "INFO": DIM}


def main():
    parser_ = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser_.add_argument("url", help="Target URL, e.g. https://example.com (must be authorized)")
    parser_.add_argument("--report", action="store_true", help="Generate an HTML report")
    args = parser_.parse_args()

    print(BANNER)
    print(f"{DIM}⚠ Only scan sites you own or are authorized to test.{RESET}\n")
    print(f"{GREEN}[*]{RESET} Target: {args.url}\n")

    results = webscan.scan(args.url)
    all_findings = results["headers"] + results["ssl"] + results["exposed_files"]

    if not all_findings:
        print(f"{GREEN}[+] No issues found (or target unreachable).{RESET}")
    for f in all_findings:
        color = SEV_COLOR.get(f["severity"], DIM)
        print(f"  {color}[{f['severity']:6}]{RESET} {f['check']:28} {f['detail']}")

    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"\n{BOLD}Summary:{RESET} {RED}{high} high{RESET}, {YELLOW}{med} medium{RESET}, "
          f"{len(all_findings) - high - med} other")

    if args.report:
        path = report.generate_html_report(results, all_findings)
        print(f"\n{GREEN}[*] HTML report written to: {path}{RESET}")


if __name__ == "__main__":
    main()
