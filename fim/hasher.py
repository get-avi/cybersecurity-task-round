"""
Multi-threaded cryptographic hashing engine.
Supports chunked reading of large files to maintain low memory footprint.
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer


def compute_file_hash(
    file_path: Path,
    algorithm: str = "sha256"
) -> Optional[Dict[str, Any]]:
    """
    Computes cryptographic hash and metadata for a single file using streaming chunks.
    Gracefully handles permission and I/O errors.
    """
    try:
        if not file_path.is_file():
            return None

        stat = file_path.stat()
        hasher = hashlib.new(algorithm)

        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)

        return {
            "path": str(file_path.resolve()),
            "hash": hasher.hexdigest(),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "error": None
        }

    except PermissionError:
        return {
            "path": str(file_path.resolve()),
            "hash": None,
            "size": 0,
            "mtime": 0,
            "error": "PermissionDenied"
        }
    except FileNotFoundError:
        return None
    except Exception as exc:
        return {
            "path": str(file_path.resolve()),
            "hash": None,
            "size": 0,
            "mtime": 0,
            "error": str(exc)
        }


def scan_directory(
    target_dir: Path,
    workers: int = 4,
    algorithm: str = "sha256",
    excluded_files: Optional[Set[str]] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Recursively scans target directory and computes hashes concurrently using ThreadPoolExecutor.
    
    Args:
        target_dir: Directory path to scan.
        workers: Number of concurrent hashing threads.
        algorithm: Hashing algorithm (sha256, sha512, md5).
        excluded_files: Filenames or paths to ignore (e.g. baseline or log files).

    Returns:
        Mapping of relative file path string -> file metadata dictionary.
    """
    target_dir = target_dir.resolve()
    if not target_dir.is_dir():
        raise NotADirectoryError(f"Target path '{target_dir}' is not a valid directory.")

    excluded = excluded_files or set()
    files_to_scan: List[Path] = []

    for root, dirs, files in os.walk(target_dir):
        # Ignore hidden directories like .git
        dirs[:] = [d for d in dirs if not d.startswith(".git")]
        for file in files:
            full_path = Path(root) / file
            # Check exclusions
            if full_path.name in excluded or str(full_path) in excluded:
                continue
            if full_path.is_file():
                files_to_scan.append(full_path)

    results: Dict[str, Dict[str, Any]] = {}

    if not files_to_scan:
        return results

    # Execute concurrent hashing via worker pool
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        future_to_path = {
            executor.submit(compute_file_hash, path, algorithm): path
            for path in files_to_scan
        }

        for future in as_completed(future_to_path):
            file_info = future.result()
            if file_info:
                # Use path relative to target_dir for portable baseline manifests
                try:
                    rel_path = Path(file_info["path"]).relative_to(target_dir).as_posix()
                except ValueError:
                    rel_path = file_info["path"]
                results[rel_path] = file_info

    return results
