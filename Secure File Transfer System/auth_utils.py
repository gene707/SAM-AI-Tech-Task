import hmac
import hashlib
import os

class AuthManager:
    """Handles mutual challenge-response HMAC authentication between client and server."""

    @staticmethod
    def generate_challenge() -> bytes:
        """Generates random 32-byte challenge nonce."""
        return os.urandom(32)

    @staticmethod
    def compute_response(challenge: bytes, auth_key: str) -> str:
        """Computes HMAC-SHA256 hex digest of challenge using secret auth_key."""
        key_bytes = auth_key.encode('utf-8')
        return hmac.new(key_bytes, challenge, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_response(challenge: bytes, response_hex: str, auth_key: str) -> bool:
        """Verifies received HMAC response matches expected HMAC digest."""
        expected_hex = AuthManager.compute_response(challenge, auth_key)
        return hmac.compare_digest(expected_hex.lower(), response_hex.strip().lower())
