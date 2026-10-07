import unittest
import os
import sys
import time
import shutil
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_utils import CryptoUtils
from auth_utils import AuthManager
from history_logger import HistoryLogger
from transfer_server import SecureTransferServer
from transfer_client import SecureTransferClient

class TestSecureFileTransfer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_file = os.path.join(self.test_dir, "confidential_document.txt")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write("TOP SECRET DEEP MIND ANTIMATTER EXPERIMENT PROTOCOL DATA")

        self.auth_key = "super_secret_auth_token_999"
        self.secret_key = "my_strong_encryption_passphrase"
        self.history_file = os.path.join(self.test_dir, "test_history.json")
        self.received_dir = os.path.join(self.test_dir, "received")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_crypto_encryption_decryption(self):
        enc_bytes, orig_sha = CryptoUtils.encrypt_file(self.sample_file, self.secret_key)
        out_dec = os.path.join(self.test_dir, "decrypted.txt")
        
        ok, dec_sha, _ = CryptoUtils.decrypt_and_save(enc_bytes, self.secret_key, out_dec, orig_sha)
        self.assertTrue(ok)
        self.assertEqual(orig_sha, dec_sha)

        with open(out_dec, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertEqual(content, "TOP SECRET DEEP MIND ANTIMATTER EXPERIMENT PROTOCOL DATA")

    def test_auth_manager_verification(self):
        challenge = AuthManager.generate_challenge()
        valid_response = AuthManager.compute_response(challenge, self.auth_key)
        
        self.assertTrue(AuthManager.verify_response(challenge, valid_response, self.auth_key))
        self.assertFalse(AuthManager.verify_response(challenge, valid_response, "wrong_auth_key"))

    def test_history_logger(self):
        logger = HistoryLogger(self.history_file)
        logger.log_transfer("SEND", "127.0.0.1:9000", "test.txt", 1024, "dummyhash", "SUCCESS")
        
        history = logger.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["filename"], "test.txt")
        self.assertEqual(history[0]["status"], "SUCCESS")

    def test_full_client_server_transfer(self):
        port = 9876
        server = SecureTransferServer("127.0.0.1", port, self.auth_key, self.secret_key, self.received_dir, self.history_file)

        # Run server handling 1 connection in background thread
        server_thread = threading.Thread(target=server.start, kwargs={"max_connections": 1}, daemon=True)
        server_thread.start()
        time.sleep(0.3)  # Allow socket to bind

        client = SecureTransferClient("127.0.0.1", port, self.auth_key, self.secret_key, self.history_file)
        success = client.send_file(self.sample_file)
        
        server_thread.join(timeout=3.0)
        self.assertTrue(success)

        # Check file received in output dir
        recv_path = os.path.join(self.received_dir, "confidential_document.txt")
        self.assertTrue(os.path.exists(recv_path))
        
        orig_sha = CryptoUtils.calculate_sha256(self.sample_file)
        recv_sha = CryptoUtils.calculate_sha256(recv_path)
        self.assertEqual(orig_sha, recv_sha)

if __name__ == "__main__":
    unittest.main()
