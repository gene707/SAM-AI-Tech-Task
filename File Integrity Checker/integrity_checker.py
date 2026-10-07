import os
import hashlib
import json
import datetime
from typing import Dict, List, Tuple, Optional, Any

class HashCalculator:
    """Calculates file hashes using specified algorithms (SHA-256, MD5, SHA-512, SHA-1)."""
    
    SUPPORTED_ALGORITHMS = ["sha256", "md5", "sha512", "sha1"]
    
    @staticmethod
    def calculate_hash(file_path: str, algorithm: str = "sha256") -> str:
        algo = algorithm.lower()
        if algo not in HashCalculator.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {', '.join(HashCalculator.SUPPORTED_ALGORITHMS)}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        hasher = getattr(hashlib, algo)()
        buffer_size = 65536  # 64kb chunks
        
        with open(file_path, "rb") as f:
            while chunk := f.read(buffer_size):
                hasher.update(chunk)
                
        return hasher.hexdigest()

    @staticmethod
    def calculate_multiple(file_paths: List[str], algorithm: str = "sha256") -> Dict[str, Optional[str]]:
        results = {}
        for path in file_paths:
            try:
                results[path] = HashCalculator.calculate_hash(path, algorithm)
            except Exception as e:
                results[path] = None
        return results


class HashComparator:
    """Compares hashes of files or explicit hash strings."""
    
    @staticmethod
    def compare_file_with_hash(file_path: str, expected_hash: str, algorithm: str = "sha256") -> Tuple[bool, str, str]:
        actual_hash = HashCalculator.calculate_hash(file_path, algorithm)
        matches = actual_hash.lower() == expected_hash.strip().lower()
        return matches, actual_hash, expected_hash.strip().lower()

    @staticmethod
    def compare_two_files(file1_path: str, file2_path: str, algorithm: str = "sha256") -> Tuple[bool, str, str]:
        hash1 = HashCalculator.calculate_hash(file1_path, algorithm)
        hash2 = HashCalculator.calculate_hash(file2_path, algorithm)
        return hash1.lower() == hash2.lower(), hash1, hash2


class BaselineManager:
    """Creates baseline hash manifests and detects file modifications across directories."""
    
    def __init__(self, target_dir: str, algorithm: str = "sha256"):
        self.target_dir = os.path.abspath(target_dir)
        self.algorithm = algorithm.lower()

    def generate_baseline(self, output_file: str) -> Dict[str, Any]:
        manifest_entries = {}
        file_count = 0
        
        for root, _, files in os.walk(self.target_dir):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, self.target_dir)
                try:
                    file_hash = HashCalculator.calculate_hash(full_path, self.algorithm)
                    stat_info = os.stat(full_path)
                    manifest_entries[rel_path] = {
                        "hash": file_hash,
                        "size": stat_info.st_size,
                        "mtime": datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                    }
                    file_count += 1
                except Exception as e:
                    manifest_entries[rel_path] = {
                        "hash": None,
                        "error": str(e)
                    }

        baseline_data = {
            "target_dir": self.target_dir,
            "algorithm": self.algorithm,
            "created_at": datetime.datetime.now().isoformat(),
            "total_files": file_count,
            "files": manifest_entries
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2)

        return baseline_data

    def verify_baseline(self, baseline_file: str) -> Dict[str, Any]:
        if not os.path.exists(baseline_file):
            raise FileNotFoundError(f"Baseline manifest file not found: {baseline_file}")

        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)

        saved_files = baseline_data.get("files", {})
        algo = baseline_data.get("algorithm", self.algorithm)

        intact = []
        modified = []
        deleted = []
        added = []

        # Current files on disk
        current_rel_paths = set()
        for root, _, files in os.walk(self.target_dir):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(full_path, self.target_dir)
                current_rel_paths.add(rel_path)

        saved_rel_paths = set(saved_files.keys())

        # Check existing baseline entries
        for rel_path, entry in saved_files.items():
            full_path = os.path.join(self.target_dir, rel_path)
            if not os.path.exists(full_path):
                deleted.append({"path": rel_path, "expected_hash": entry.get("hash")})
            else:
                try:
                    current_hash = HashCalculator.calculate_hash(full_path, algo)
                    if current_hash.lower() == entry.get("hash", "").lower():
                        intact.append({"path": rel_path, "hash": current_hash})
                    else:
                        modified.append({
                            "path": rel_path,
                            "expected_hash": entry.get("hash"),
                            "actual_hash": current_hash
                        })
                except Exception as e:
                    modified.append({
                        "path": rel_path,
                        "expected_hash": entry.get("hash"),
                        "error": str(e)
                    })

        # Check for newly added files
        new_paths = current_rel_paths - saved_rel_paths
        for rel_path in sorted(new_paths):
            full_path = os.path.join(self.target_dir, rel_path)
            try:
                current_hash = HashCalculator.calculate_hash(full_path, algo)
                added.append({"path": rel_path, "hash": current_hash})
            except Exception as e:
                added.append({"path": rel_path, "error": str(e)})

        return {
            "target_dir": self.target_dir,
            "algorithm": algo,
            "baseline_date": baseline_data.get("created_at"),
            "verification_date": datetime.datetime.now().isoformat(),
            "summary": {
                "intact": len(intact),
                "modified": len(modified),
                "deleted": len(deleted),
                "added": len(added),
                "total_checked": len(saved_files) + len(added)
            },
            "intact": intact,
            "modified": modified,
            "deleted": deleted,
            "added": added
        }
