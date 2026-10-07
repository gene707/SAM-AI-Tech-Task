import os
import json
import datetime
from typing import Dict, List, Any

class HistoryLogger:
    """Logs and reads transfer history records."""

    def __init__(self, log_path: str = "transfer_history.json"):
        self.log_path = os.path.abspath(log_path)

    def log_transfer(self, action: str, peer: str, filename: str, file_size: int, sha256_hash: str, status: str, detail: str = "") -> Dict[str, Any]:
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "action": action.upper(),  # "SEND" or "RECEIVE"
            "peer": peer,
            "filename": filename,
            "file_size": file_size,
            "sha256": sha256_hash,
            "status": status,  # "SUCCESS", "AUTH_FAILED", "INTEGRITY_MISMATCH", "DECRYPTION_ERROR"
            "detail": detail
        }

        history = self.get_history()
        history.append(entry)

        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print(f"[WARN] Failed to write transfer history log: {e}")

        return entry

    def get_history(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
