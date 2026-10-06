"""
Automated Unit & Integration Tests for File Integrity Monitor (FIM).
Tests cryptographic hashing, baseline generation, and delta detection for
CREATED, MODIFIED, and DELETED file states.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fim.hasher import compute_file_hash, scan_directory
from fim.detector import BaselineManager, ChangeDetector


class TestFileIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        """Create a sandboxed temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp(prefix="fim_test_")
        self.test_path = Path(self.test_dir)
        # Store baseline in a separate temp path so it doesn't pollute the target directory
        self.baseline_path = self.test_path.parent / f"{self.test_path.name}_baseline.json"

        # Create sample files
        self.file_a = self.test_path / "config.conf"
        self.file_a.write_text("SERVER_PORT=8080\nDEBUG=False\n")

        self.file_b = self.test_path / "secrets.env"
        self.file_b.write_text("DB_KEY=s3cr3t_p@ss\n")

        self.sub_dir = self.test_path / "subfolder"
        self.sub_dir.mkdir()
        self.file_c = self.sub_dir / "app.py"
        self.file_c.write_text("print('Production server running')\n")

    def tearDown(self):
        """Clean up temporary test artifacts."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if self.baseline_path.exists():
            self.baseline_path.unlink()

    def test_single_file_hash(self):
        """Verify deterministic SHA-256 calculation."""
        res = compute_file_hash(self.file_a, "sha256")
        self.assertIsNotNone(res)
        self.assertIn("hash", res)
        self.assertEqual(len(res["hash"]), 64)  # 64 hex characters for SHA-256
        self.assertEqual(res["error"], None)

    def test_baseline_creation(self):
        """Test initial baseline generation and JSON schema."""
        files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        self.assertEqual(len(files), 3)

        manager = BaselineManager(self.baseline_path)
        manifest = manager.save_baseline(self.test_path, "sha256", files)

        self.assertTrue(self.baseline_path.exists())
        self.assertEqual(manifest["metadata"]["total_files"], 3)
        self.assertIn("config.conf", manifest["files"])
        self.assertIn("secrets.env", manifest["files"])

    def test_unaltered_directory_verification(self):
        """Verify that an untouched directory produces zero integrity violations."""
        files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        manager = BaselineManager(self.baseline_path)
        manager.save_baseline(self.test_path, "sha256", files)

        current_files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        deltas = ChangeDetector.evaluate_deltas(files, current_files)

        self.assertEqual(deltas["total_violations"], 0)
        self.assertEqual(len(deltas["created"]), 0)
        self.assertEqual(len(deltas["modified"]), 0)
        self.assertEqual(len(deltas["deleted"]), 0)
        self.assertEqual(len(deltas["unchanged"]), 3)

    def test_file_modification_detection(self):
        """Tamper with a file and assert MODIFIED alert is triggered."""
        files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        original_hash = files["config.conf"]["hash"]

        # Simulate tampering
        self.file_a.write_text("SERVER_PORT=9999\nDEBUG=True\nBACKDOOR=Active\n")

        current_files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        deltas = ChangeDetector.evaluate_deltas(files, current_files)

        self.assertEqual(deltas["total_violations"], 1)
        self.assertEqual(len(deltas["modified"]), 1)
        mod_event = deltas["modified"][0]
        self.assertEqual(mod_event["file"], "config.conf")
        self.assertEqual(mod_event["baseline_hash"], original_hash)
        self.assertNotEqual(mod_event["current_hash"], original_hash)

    def test_file_creation_detection(self):
        """Add unauthorized file and assert CREATED alert is triggered."""
        files = scan_directory(self.test_path, workers=2, algorithm="sha256")

        # Inject new rogue file
        rogue_file = self.test_path / "malicious_script.sh"
        rogue_file.write_text("#!/bin/bash\ncat /etc/shadow\n")

        current_files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        deltas = ChangeDetector.evaluate_deltas(files, current_files)

        self.assertEqual(deltas["total_violations"], 1)
        self.assertEqual(len(deltas["created"]), 1)
        self.assertEqual(deltas["created"][0]["file"], "malicious_script.sh")

    def test_file_deletion_detection(self):
        """Delete an authorized file and assert DELETED alert is triggered."""
        files = scan_directory(self.test_path, workers=2, algorithm="sha256")

        # Delete secrets file
        self.file_b.unlink()

        current_files = scan_directory(self.test_path, workers=2, algorithm="sha256")
        deltas = ChangeDetector.evaluate_deltas(files, current_files)

        self.assertEqual(deltas["total_violations"], 1)
        self.assertEqual(len(deltas["deleted"]), 1)
        self.assertEqual(deltas["deleted"][0]["file"], "secrets.env")


if __name__ == "__main__":
    unittest.main()
