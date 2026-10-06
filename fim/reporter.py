"""
Output formatting and structured alert logging for FIM.
Provides colored console notifications and machine-readable JSON logs.
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, List


# ANSI Color Codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
  [FIM] File Integrity Monitor & Defensive Tamper Detection Engine
  Automated Host Intrusion Detection System (HIDS) Tool
======================================================================{Colors.RESET}"""
    print(banner)


def format_cli_report(audit_result: Dict[str, Any], verbose: bool = False):
    """Prints a human-readable, colorized terminal summary."""
    violations = audit_result["total_violations"]
    scanned = audit_result["total_files_scanned"]
    timestamp = audit_result["timestamp"]

    print(f"\n{Colors.BOLD}[*] Audit Timestamp:{Colors.RESET} {timestamp}")
    print(f"{Colors.BOLD}[*] Files Inspected:{Colors.RESET} {scanned}")

    if violations == 0:
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] STATUS: INTEGRITY VERIFIED - No unauthorized changes detected.{Colors.RESET}\n")
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}[!] ALERT: INTEGRITY COMPROMISED - {violations} deviation(s) detected!{Colors.RESET}\n")

    # Display Created
    for item in audit_result["created"]:
        print(
            f"  {Colors.YELLOW}[+] NEW FILE DETECTED:{Colors.RESET} {item['file']}\n"
            f"      {Colors.GRAY}SHA-256:{Colors.RESET} {item['current_hash']} ({item['size']} bytes)"
        )

    # Display Modified
    for item in audit_result["modified"]:
        print(
            f"  {Colors.RED}{Colors.BOLD}[!] TAMPERING DETECTED (MODIFIED):{Colors.RESET} {item['file']}\n"
            f"      {Colors.GRAY}Baseline Hash:{Colors.RESET} {item['baseline_hash']}\n"
            f"      {Colors.RED}Current  Hash:{Colors.RESET} {item['current_hash']}"
        )

    # Display Deleted
    for item in audit_result["deleted"]:
        print(
            f"  {Colors.RED}[-] FILE DELETED/MISSING:{Colors.RESET} {item['file']}\n"
            f"      {Colors.GRAY}Expected Hash:{Colors.RESET} {item['baseline_hash']}"
        )

    if verbose and audit_result["unchanged"]:
        print(f"\n{Colors.GRAY}[*] Unchanged Files ({len(audit_result['unchanged'])}):{Colors.RESET}")
        for path in audit_result["unchanged"]:
            print(f"      - {path}")

    print(f"{Colors.CYAN}{'-'*70}{Colors.RESET}")


def append_json_log(log_path: Path, audit_result: Dict[str, Any]):
    """Appends audit event violations to a structured JSON Lines alert file."""
    if audit_result["total_violations"] == 0:
        return

    log_path = Path(log_path).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    log_entry = {
        "timestamp": audit_result["timestamp"],
        "violations_count": audit_result["total_violations"],
        "events": (
            audit_result["created"] +
            audit_result["modified"] +
            audit_result["deleted"]
        )
    }

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")
