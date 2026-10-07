import socket
import json
import os
from crypto_utils import CryptoUtils
from auth_utils import AuthManager
from history_logger import HistoryLogger

class SecureTransferClient:
    """TCP Client to encrypt files, authenticate, transmit over socket, and verify integrity."""

    def __init__(self, host: str, port: int, auth_key: str, secret_key: str, history_log: str = "transfer_history.json"):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.secret_key = secret_key
        self.logger = HistoryLogger(history_log)

    def send_file(self, file_path: str) -> bool:
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File to send not found: {file_path}")

        filename = os.path.basename(file_path)
        print(f"[CLIENT] Encrypting '{filename}'...")
        encrypted_bytes, orig_sha256 = CryptoUtils.encrypt_file(file_path, self.secret_key)
        orig_size = os.path.getsize(file_path)
        enc_size = len(encrypted_bytes)

        print(f"[CLIENT] Original Size: {orig_size} bytes | Encrypted Size: {enc_size} bytes")
        print(f"[CLIENT] Original SHA-256: {orig_sha256}")
        print(f"[CLIENT] Connecting to server {self.host}:{self.port}...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.host, self.port))

            # 1. Handshake Authentication
            challenge = sock.recv(1024)
            auth_response = AuthManager.compute_response(challenge, self.auth_key)
            sock.sendall((auth_response + "\n").encode('utf-8'))

            auth_status = sock.recv(1024).decode('utf-8').strip()
            if auth_status != "AUTH_OK":
                print(f"[CLIENT ERR] Authentication rejected by server: {auth_status}")
                self.logger.log_transfer("SEND", f"{self.host}:{self.port}", filename, orig_size, orig_sha256, "AUTH_FAILED", "Server rejected auth response")
                return False

            print("[CLIENT AUTH] Handshake authentication successful!")

            # 2. Transmit Metadata Header
            metadata = {
                "filename": filename,
                "orig_sha256": orig_sha256,
                "encrypted_size": enc_size
            }
            header_json = json.dumps(metadata) + "\n"
            sock.sendall(header_json.encode('utf-8'))

            header_status = sock.recv(1024).decode('utf-8').strip()
            if header_status != "HEADER_OK":
                print(f"[CLIENT ERR] Header rejected by server: {header_status}")
                self.logger.log_transfer("SEND", f"{self.host}:{self.port}", filename, orig_size, orig_sha256, "FAILED", f"Header rejected: {header_status}")
                return False

            # 3. Stream Encrypted Payload
            print("[CLIENT] Transmitting encrypted file data...")
            sock.sendall(encrypted_bytes)

            # 4. Receive Final Status Confirmation
            final_status = sock.recv(1024).decode('utf-8').strip()
            print(f"[CLIENT] Transfer Server Response: {final_status}")

            if final_status == "TRANSFER_SUCCESS":
                print(f"[SUCCESS] File '{filename}' transferred and verified successfully.")
                self.logger.log_transfer("SEND", f"{self.host}:{self.port}", filename, orig_size, orig_sha256, "SUCCESS", "File delivered and verified intact")
                return True
            else:
                print(f"[WARNING] Transfer completed with warning status: {final_status}")
                self.logger.log_transfer("SEND", f"{self.host}:{self.port}", filename, orig_size, orig_sha256, "FAILED", f"Server response: {final_status}")
                return False

        except Exception as e:
            print(f"[CLIENT ERR] File transfer failed: {e}")
            self.logger.log_transfer("SEND", f"{self.host}:{self.port}", filename, orig_size, orig_sha256, "FAILED", str(e))
            return False
        finally:
            sock.close()
