"""
Integrity change detection and baseline database management engine.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


class BaselineManager:
    """Manages serialization and validation of directory baseline manifests."""

    def __init__(self, baseline_path: Path):
        self.baseline_path = Path(baseline_path).resolve()

    def save_baseline(
        self,
        target_dir: Path,
        algorithm: str,
        files_map: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Saves a fresh baseline catalog to the specified JSON path."""
        manifest = {
            "metadata": {
                "version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target_directory": str(Path(target_dir).resolve()),
                "algorithm": algorithm,
                "total_files": len(files_map),
            },
            "files": files_map
        }

        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        return manifest

    def load_baseline(self) -> Dict[str, Any]:
        """Loads and parses an existing baseline file."""
        if not self.baseline_path.exists():
            raise FileNotFoundError(
                f"Baseline file '{self.baseline_path}' does not exist. Run with --init-baseline first."
            )

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as err:
                raise ValueError(f"Corrupted baseline JSON file: {err}")

        if "files" not in data:
            raise ValueError("Invalid baseline schema: Missing 'files' key.")

        return data


class ChangeDetector:
    """Compares current filesystem scan against the established baseline."""

    @staticmethod
    def evaluate_deltas(
        baseline_files: Dict[str, Dict[str, Any]],
        current_files: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculates differences between baseline and current state.

        Returns categorized lists of events:
            - created: Files present now but absent in baseline
            - modified: Files present in both but with differing cryptographic hash
            - deleted: Files present in baseline but absent now
            - unchanged: Files with matching hashes
        """
        created: List[Dict[str, Any]] = []
        modified: List[Dict[str, Any]] = []
        deleted: List[Dict[str, Any]] = []
        unchanged: List[str] = []

        baseline_keys = set(baseline_files.keys())
        current_keys = set(current_files.keys())

        # Check for newly created files
        for path in current_keys - baseline_keys:
            info = current_files[path]
            created.append({
                "type": "CREATED",
                "file": path,
                "current_hash": info.get("hash"),
                "size": info.get("size"),
                "detected_at": datetime.now(timezone.utc).isoformat()
            })

        # Check for deleted files
        for path in baseline_keys - current_keys:
            info = baseline_files[path]
            deleted.append({
                "type": "DELETED",
                "file": path,
                "baseline_hash": info.get("hash"),
                "detected_at": datetime.now(timezone.utc).isoformat()
            })

        # Check for modified or unchanged files
        for path in baseline_keys & current_keys:
            base_info = baseline_files[path]
            curr_info = current_files[path]

            base_hash = base_info.get("hash")
            curr_hash = curr_info.get("hash")

            if base_hash != curr_hash:
                modified.append({
                    "type": "MODIFIED",
                    "file": path,
                    "baseline_hash": base_hash,
                    "current_hash": curr_hash,
                    "baseline_size": base_info.get("size"),
                    "current_size": curr_info.get("size"),
                    "detected_at": datetime.now(timezone.utc).isoformat()
                })
            else:
                unchanged.append(path)

        total_violations = len(created) + len(modified) + len(deleted)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_files_scanned": len(current_files),
            "total_violations": total_violations,
            "created": created,
            "modified": modified,
            "deleted": deleted,
            "unchanged": unchanged
        }
