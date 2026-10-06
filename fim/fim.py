#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) CLI Tool
Main entry point for baseline creation, one-off verification, and continuous monitoring.
"""

import sys
import os
import time
import argparse
import json
from pathlib import Path

# Add project root to sys.path to allow execution both as script and module
sys.path.insert(0, str(Path(__file__).parent.parent))

from fim.hasher import scan_directory
from fim.detector import BaselineManager, ChangeDetector
from fim.reporter import print_banner, format_cli_report, append_json_log, Colors


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="FIM: High-performance File Integrity Monitor & Defensive HIDS Tool.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  1. Initialize baseline manifest for /etc or ./app:
     python -m fim.fim --init-baseline -t ./target_dir -b ./baseline.json

  2. Verify directory integrity against baseline:
     python -m fim.fim --verify -t ./target_dir -b ./baseline.json

  3. Continuously monitor with 5-second polling:
     python -m fim.fim --monitor -t ./target_dir -b ./baseline.json -i 5
        """
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--init-baseline",
        action="store_true",
        help="Generate and store a new baseline hash manifest for the target directory."
    )
    mode_group.add_argument(
        "--verify",
        action="store_true",
        help="Perform a single integrity check against an existing baseline and report deviations."
    )
    mode_group.add_argument(
        "--monitor",
        action="store_true",
        help="Continuously monitor target directory in real-time at specified intervals."
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        type=str,
        help="Path to the directory to monitor or baseline."
    )
    parser.add_argument(
        "-b", "--baseline",
        default="fim_baseline.json",
        type=str,
        help="Path to baseline JSON manifest file (default: fim_baseline.json)."
    )
    parser.add_argument(
        "-w", "--workers",
        default=4,
        type=int,
        help="Number of concurrent worker threads for hashing (default: 4)."
    )
    parser.add_argument(
        "-i", "--interval",
        default=5,
        type=int,
        help="Polling interval in seconds for --monitor mode (default: 5)."
    )
    parser.add_argument(
        "-o", "--output",
        default="fim_alerts.json",
        type=str,
        help="Path to structured JSON alert log file (default: fim_alerts.json)."
    )
    parser.add_argument(
        "--algorithm",
        default="sha256",
        choices=["sha256", "sha512", "md5"],
        help="Cryptographic hashing algorithm (default: sha256)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON results to standard output instead of colorized text."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Display all files including unchanged clean files."
    )

    return parser.parse_args()


def init_baseline_action(target_dir: Path, baseline_path: Path, workers: int, algorithm: str, as_json: bool):
    target_dir = target_dir.resolve()
    baseline_path = baseline_path.resolve()

    excluded = {baseline_path.name, "fim_alerts.json"}

    if not as_json:
        print_banner()
        print(f"{Colors.BLUE}[*] Initializing baseline for: {target_dir}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Algorithm: {algorithm.upper()} | Workers: {workers}{Colors.RESET}")

    start_time = time.time()
    files_map = scan_directory(
        target_dir=target_dir,
        workers=workers,
        algorithm=algorithm,
        excluded_files=excluded
    )
    elapsed = time.time() - start_time

    manager = BaselineManager(baseline_path)
    manifest = manager.save_baseline(target_dir, algorithm, files_map)

    if as_json:
        print(json.dumps(manifest["metadata"], indent=2))
    else:
        print(f"{Colors.GREEN}[+] Baseline created successfully!{Colors.RESET}")
        print(f"    - Target Files Cataloged: {len(files_map)}")
        print(f"    - Duration: {elapsed:.2f}s")
        print(f"    - Saved To: {baseline_path}\n")


def verify_action(target_dir: Path, baseline_path: Path, workers: int, output_log: Path, as_json: bool, verbose: bool) -> int:
    target_dir = target_dir.resolve()
    baseline_path = baseline_path.resolve()

    manager = BaselineManager(baseline_path)
    try:
        baseline_data = manager.load_baseline()
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Failed to load baseline: {e}{Colors.RESET}", file=sys.stderr)
        return 2

    algorithm = baseline_data["metadata"].get("algorithm", "sha256")
    excluded = {baseline_path.name, output_log.name}

    if not as_json:
        print_banner()
        print(f"{Colors.BLUE}[*] Auditing Directory: {target_dir}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Baseline: {baseline_path} (Algorithm: {algorithm.upper()}){Colors.RESET}")

    current_files = scan_directory(
        target_dir=target_dir,
        workers=workers,
        algorithm=algorithm,
        excluded_files=excluded
    )

    audit_result = ChangeDetector.evaluate_deltas(
        baseline_files=baseline_data["files"],
        current_files=current_files
    )

    if as_json:
        print(json.dumps(audit_result, indent=2))
    else:
        format_cli_report(audit_result, verbose=verbose)

    # Persist alerts to log file if violations exist
    if audit_result["total_violations"] > 0:
        append_json_log(output_log, audit_result)
        return 1  # Exit code 1 indicates integrity violation
    return 0


def monitor_action(target_dir: Path, baseline_path: Path, workers: int, interval: int, output_log: Path, verbose: bool):
    target_dir = target_dir.resolve()
    baseline_path = baseline_path.resolve()

    manager = BaselineManager(baseline_path)
    try:
        baseline_data = manager.load_baseline()
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Failed to load baseline: {e}{Colors.RESET}", file=sys.stderr)
        sys.exit(2)

    algorithm = baseline_data["metadata"].get("algorithm", "sha256")
    excluded = {baseline_path.name, output_log.name}

    print_banner()
    print(f"{Colors.BLUE}[*] Starting Continuous Monitoring Mode{Colors.RESET}")
    print(f"[*] Target Directory: {target_dir}")
    print(f"[*] Baseline Manifest: {baseline_path}")
    print(f"[*] Poll Interval: {interval}s | Logging to: {output_log}")
    print(f"{Colors.YELLOW}[*] Press Ctrl+C to terminate monitor.{Colors.RESET}\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            current_files = scan_directory(
                target_dir=target_dir,
                workers=workers,
                algorithm=algorithm,
                excluded_files=excluded
            )

            audit_result = ChangeDetector.evaluate_deltas(
                baseline_files=baseline_data["files"],
                current_files=current_files
            )

            if audit_result["total_violations"] > 0:
                print(f"{Colors.RED}[Iteration #{iteration}] Tampering/Modifications Detected!{Colors.RESET}")
                format_cli_report(audit_result, verbose=verbose)
                append_json_log(output_log, audit_result)
            else:
                sys.stdout.write(f"\r{Colors.GREEN}[Iteration #{iteration}] Integrity OK ({audit_result['total_files_scanned']} files) - {time.strftime('%H:%M:%S')}{Colors.RESET}")
                sys.stdout.flush()

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Monitoring halted by operator.{Colors.RESET}")


def main():
    args = parse_arguments()
    target_path = Path(args.target)
    baseline_path = Path(args.baseline)
    output_log = Path(args.output)

    if not target_path.exists():
        print(f"{Colors.RED}[ERROR] Target directory '{target_path}' does not exist.{Colors.RESET}", file=sys.stderr)
        sys.exit(2)

    try:
        if args.init_baseline:
            init_baseline_action(target_path, baseline_path, args.workers, args.algorithm, args.json)
            sys.exit(0)
        elif args.verify:
            exit_code = verify_action(target_path, baseline_path, args.workers, output_log, args.json, args.verbose)
            sys.exit(exit_code)
        elif args.monitor:
            monitor_action(target_path, baseline_path, args.workers, args.interval, output_log, args.verbose)
            sys.exit(0)
    except Exception as exc:
        print(f"{Colors.RED}[FATAL ERROR] {exc}{Colors.RESET}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
