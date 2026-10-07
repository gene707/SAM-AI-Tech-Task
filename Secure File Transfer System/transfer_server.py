import socket
import json
import os
import sys
from crypto_utils import CryptoUtils
from auth_utils import AuthManager
from history_logger import HistoryLogger

class SecureTransferServer:
    """TCP Server for accepting encrypted file transfers with authentication & integrity checks."""

    def __init__(self, host: str, port: int, auth_key: str, secret_key: str, output_dir: str = "received_files", history_log: str = "transfer_history.json"):
        self.host = host
        self.port = port
        self.auth_key = auth_key
        self.secret_key = secret_key
        self.output_dir = os.path.abspath(output_dir)
        self.logger = HistoryLogger(history_log)
        self.server_socket = None

    def start(self, max_connections: int = 0):
        os.makedirs(self.output_dir, exist_ok=True)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"[SERVER] Listening on {self.host}:{self.port}...")
        print(f"[SERVER] Saving received files to: {self.output_dir}")
        print(f"[SERVER] Waiting for client connections...\n")

        conns_handled = 0
        while True:
            try:
                conn, addr = self.server_socket.accept()
                print(f"[SERVER] Connection established with {addr[0]}:{addr[1]}")
                self._handle_client(conn, addr)
                conns_handled += 1
                if max_connections > 0 and conns_handled >= max_connections:
                    print("[SERVER] Max connections reached. Shutting down server.")
                    break
            except KeyboardInterrupt:
                print("\n[SERVER] Keyboard interrupt received. Stopping server.")
                break
            except Exception as e:
                print(f"[SERVER ERR] Error accepting connection: {e}")

        self.stop()

    def stop(self):
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _handle_client(self, conn: socket.socket, addr: tuple):
        try:
            # 1. Handshake Authentication Challenge
            challenge = AuthManager.generate_challenge()
            conn.sendall(challenge)

            # Receive Auth Response (64 hex characters + newline)
            auth_resp_raw = conn.recv(1024).decode('utf-8').strip()
            if not AuthManager.verify_response(challenge, auth_resp_raw, self.auth_key):
                print(f"[SERVER REJECT] Authentication failed for client {addr[0]}")
                conn.sendall(b"AUTH_FAIL\n")
                self.logger.log_transfer("RECEIVE", f"{addr[0]}:{addr[1]}", "UNKNOWN", 0, "", "AUTH_FAILED", "Invalid authentication key/response")
                conn.close()
                return

            conn.sendall(b"AUTH_OK\n")
            print(f"[SERVER AUTH] Client {addr[0]} authenticated successfully.")

            # 2. Receive File Metadata Header
            header_raw = b""
            while b"\n" not in header_raw:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                header_raw += chunk

            lines = header_raw.split(b"\n", 1)
            header_line = lines[0].decode('utf-8')
            metadata = json.loads(header_line)

            filename = metadata.get("filename", "received_file.bin")
            expected_sha256 = metadata.get("orig_sha256", "")
            enc_size = metadata.get("encrypted_size", 0)

            conn.sendall(b"HEADER_OK\n")

            # 3. Receive Encrypted Payload Chunks
            encrypted_data = bytearray()
            # If remaining header bytes exist after newline, append them
            if len(lines) > 1 and lines[1]:
                encrypted_data.extend(lines[1])

            while len(encrypted_data) < enc_size:
                needed = enc_size - len(encrypted_data)
                chunk = conn.recv(min(65536, needed))
                if not chunk:
                    break
                encrypted_data.extend(chunk)

            if len(encrypted_data) != enc_size:
                print(f"[SERVER ERR] Incomplete data received: {len(encrypted_data)} / {enc_size} bytes")
                conn.sendall(b"TRANSFER_INCOMPLETE\n")
                self.logger.log_transfer("RECEIVE", f"{addr[0]}:{addr[1]}", filename, enc_size, expected_sha256, "FAILED", "Incomplete data received")
                conn.close()
                return

            # 4. Decrypt File & Verify Integrity
            save_path = os.path.join(self.output_dir, filename)
            integrity_ok, actual_sha256, _ = CryptoUtils.decrypt_and_save(
                bytes(encrypted_data), self.secret_key, save_path, expected_sha256
            )

            if integrity_ok:
                print(f"[SERVER SUCCESS] File '{filename}' decrypted & verified. SHA-256: {actual_sha256}")
                conn.sendall(b"TRANSFER_SUCCESS\n")
                self.logger.log_transfer("RECEIVE", f"{addr[0]}:{addr[1]}", filename, os.path.getsize(save_path), actual_sha256, "SUCCESS", f"Saved to {save_path}")
            else:
                print(f"[SERVER WARN] File '{filename}' integrity verification failed! (Expected: {expected_sha256}, Actual: {actual_sha256})")
                conn.sendall(b"INTEGRITY_MISMATCH\n")
                self.logger.log_transfer("RECEIVE", f"{addr[0]}:{addr[1]}", filename, len(encrypted_data), actual_sha256, "INTEGRITY_MISMATCH", f"Expected {expected_sha256}")

        except Exception as e:
            print(f"[SERVER ERR] Error during transfer handling: {e}")
            try:
                conn.sendall(f"SERVER_ERROR: {e}\n".encode('utf-8'))
            except Exception:
                pass
            self.logger.log_transfer("RECEIVE", f"{addr[0]}:{addr[1]}", "ERROR", 0, "", "FAILED", str(e))
        finally:
            conn.close()
