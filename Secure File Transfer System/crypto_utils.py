import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Tuple

class CryptoUtils:
    """Handles key derivation, file encryption, decryption, and hash calculation."""

    @staticmethod
    def generate_key() -> str:
        """Generates a random URL-safe 32-byte Fernet base64 key string."""
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes = b'antigravity_salt_123') -> str:
        """Derives a Fernet key from a plain text password or passphrase using PBKDF2HMAC."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
        return key.decode('utf-8')

    @staticmethod
    def get_fernet_instance(key_or_passphrase: str) -> Fernet:
        """Parses key string as Fernet key or derives key from passphrase if invalid base64 key."""
        try:
            # Try loading directly as base64 Fernet key
            return Fernet(key_or_passphrase.encode('utf-8'))
        except Exception:
            # Derive Fernet key from passphrase
            derived = CryptoUtils.derive_key_from_passphrase(key_or_passphrase)
            return Fernet(derived.encode('utf-8'))

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculates SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def encrypt_bytes(data: bytes, key_or_passphrase: str) -> bytes:
        fernet = CryptoUtils.get_fernet_instance(key_or_passphrase)
        return fernet.encrypt(data)

    @staticmethod
    def decrypt_bytes(encrypted_data: bytes, key_or_passphrase: str) -> bytes:
        fernet = CryptoUtils.get_fernet_instance(key_or_passphrase)
        return fernet.decrypt(encrypted_data)

    @staticmethod
    def encrypt_file(input_file: str, key_or_passphrase: str) -> Tuple[bytes, str]:
        """Encrypts file content and returns (encrypted_bytes, sha256_hash_of_original)."""
        sha256_hash = CryptoUtils.calculate_sha256(input_file)
        with open(input_file, "rb") as f:
            raw_bytes = f.read()
        encrypted_bytes = CryptoUtils.encrypt_bytes(raw_bytes, key_or_passphrase)
        return encrypted_bytes, sha256_hash

    @staticmethod
    def decrypt_and_save(encrypted_bytes: bytes, key_or_passphrase: str, output_file: str, expected_sha256: str) -> Tuple[bool, str, str]:
        """Decrypts bytes, saves to output_file, and verifies SHA-256 integrity."""
        raw_bytes = CryptoUtils.decrypt_bytes(encrypted_bytes, key_or_passphrase)
        
        # Write to file
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "wb") as f:
            f.write(raw_bytes)

        actual_sha256 = CryptoUtils.calculate_sha256(output_file)
        integrity_ok = actual_sha256.lower() == expected_sha256.lower()
        return integrity_ok, actual_sha256, expected_sha256
