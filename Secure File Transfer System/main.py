import argparse
import sys
import os
import json
import threading
import time
from crypto_utils import CryptoUtils
from history_logger import HistoryLogger
from transfer_server import SecureTransferServer
from transfer_client import SecureTransferClient

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "app_name": "Secure File Transfer System",
        "default_host": "127.0.0.1",
        "default_port": 9000,
        "received_files_dir": "received_files",
        "history_file": "transfer_history.json"
    }

def save_config(config):
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def print_banner(app_name):
    border = "=" * (len(app_name) + 12)
    print(f"\n{border}")
    print(f"  [>] {app_name}  ")
    print(f"{border}\n")

def display_history(config):
    logger = HistoryLogger(config.get("history_file", "transfer_history.json"))
    records = logger.get_history()
    print("\n================ TRANSFER HISTORY LOG ==================")
    if not records:
        print("No transfer history records found.")
    else:
        for idx, r in enumerate(records, 1):
            print(f"#{idx} [{r['timestamp']}] Action: {r['action']} | Peer: {r['peer']}")
            print(f"   File: {r['filename']} ({r['file_size']} bytes) | SHA-256: {r.get('sha256', '')[:12]}...")
            print(f"   Status: {r['status']} | Detail: {r.get('detail', '')}")
            print("--------------------------------------------------------")
    print("========================================================\n")

def interactive_mode(app_name):
    config = load_config()
    current_name = app_name or config.get("app_name", "Secure File Transfer System")

    while True:
        print_banner(current_name)
        print("Select an option:")
        print("1. Start Receiver Server")
        print("2. Send Encrypted File to Server")
        print("3. Generate New Cryptographic Key / Passphrase")
        print("4. Local File Encrypt / Decrypt Helper")
        print("5. View Transfer History Logs")
        print("6. Change Application Name (Current: '{}')".format(current_name))
        print("0. Exit")

        choice = input("\nEnter choice (0-6): ").strip()

        if choice == "1":
            host = input(f"Enter host to bind [default: {config.get('default_host', '127.0.0.1')}]: ").strip() or config.get("default_host", "127.0.0.1")
            port = int(input(f"Enter port [default: {config.get('default_port', 9000)}]: ").strip() or config.get("default_port", 9000))
            auth_key = input("Enter Auth Secret Key (for sender authentication): ").strip()
            secret_key = input("Enter Encryption Key / Passphrase: ").strip()
            out_dir = input(f"Enter output directory [default: {config.get('received_files_dir', 'received_files')}]: ").strip() or config.get("received_files_dir", "received_files")

            if not auth_key or not secret_key:
                print("[ERR] Both Auth Secret Key and Encryption Key are required!")
                continue

            srv = SecureTransferServer(host, port, auth_key, secret_key, out_dir, config.get("history_file", "transfer_history.json"))
            srv.start()

        elif choice == "2":
            file_path = input("Enter file path to send: ").strip('"\' ')
            if not os.path.exists(file_path):
                print(f"[ERR] File not found: {file_path}")
                continue

            host = input(f"Enter server host [default: {config.get('default_host', '127.0.0.1')}]: ").strip() or config.get("default_host", "127.0.0.1")
            port = int(input(f"Enter server port [default: {config.get('default_port', 9000)}]: ").strip() or config.get("default_port", 9000))
            auth_key = input("Enter Auth Secret Key: ").strip()
            secret_key = input("Enter Encryption Key / Passphrase: ").strip()

            if not auth_key or not secret_key:
                print("[ERR] Both Auth Secret Key and Encryption Key are required!")
                continue

            client = SecureTransferClient(host, port, auth_key, secret_key, config.get("history_file", "transfer_history.json"))
            client.send_file(file_path)

        elif choice == "3":
            new_key = CryptoUtils.generate_key()
            print("\n---------------- GENERATED KEY ----------------")
            print(f"Random Fernet Key: {new_key}")
            print("------------------------------------------------")
            print("Tip: You can use this key string OR any strong passphrase for encryption.\n")

        elif choice == "4":
            print("\nLocal Encryption / Decryption Helper:")
            print("a. Encrypt file locally")
            print("b. Decrypt file locally")
            sub = input("Choose (a/b): ").strip().lower()
            if sub == "a":
                src = input("Enter input file path: ").strip('"\' ')
                dst = input("Enter encrypted output file path: ").strip('"\' ')
                k = input("Enter encryption key/passphrase: ").strip()
                if os.path.exists(src) and dst and k:
                    enc_bytes, sha = CryptoUtils.encrypt_file(src, k)
                    with open(dst, "wb") as f:
                        f.write(enc_bytes)
                    print(f"\n[SUCCESS] File encrypted and saved to '{dst}'. Original SHA-256: {sha}")
            elif sub == "b":
                src = input("Enter encrypted file path: ").strip('"\' ')
                dst = input("Enter decrypted output file path: ").strip('"\' ')
                k = input("Enter encryption key/passphrase: ").strip()
                expected_sha = input("Enter expected original SHA-256 hash (optional): ").strip()
                if os.path.exists(src) and dst and k:
                    with open(src, "rb") as f:
                        enc_data = f.read()
                    try:
                        ok, actual_sha, _ = CryptoUtils.decrypt_and_save(enc_data, k, dst, expected_sha)
                        print(f"\n[SUCCESS] File decrypted and saved to '{dst}'. Decrypted SHA-256: {actual_sha}")
                        if expected_sha and not ok:
                            print("[WARN] Integrity hash mismatch!")
                    except Exception as e:
                        print(f"[ERR] Decryption failed: {e}")

        elif choice == "5":
            display_history(config)

        elif choice == "6":
            new_name = input(f"Enter new application name [current: '{current_name}']: ").strip()
            if new_name:
                current_name = new_name
                config["app_name"] = new_name
                save_config(config)
                print(f"\n[SUCCESS] Application name updated to '{current_name}'.")

        elif choice == "0":
            print("\nExiting Secure File Transfer System. Goodbye!")
            sys.exit(0)
        else:
            print("[!] Invalid option.")

def main():
    config = load_config()
    default_app_name = config.get("app_name", "Secure File Transfer System")

    parser = argparse.ArgumentParser(description="Secure File Transfer System (Terminal Version)")
    parser.add_argument("-n", "--name", type=str, default=default_app_name, help="Set custom application name")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Keygen command
    subparsers.add_parser("keygen", help="Generate a random Fernet 32-byte key")

    # History command
    subparsers.add_parser("history", help="View transfer history log")

    # Server command
    srv_parser = subparsers.add_parser("server", help="Run transfer receiver server")
    srv_parser.add_argument("--host", type=str, default=config.get("default_host", "127.0.0.1"))
    srv_parser.add_argument("--port", type=int, default=config.get("default_port", 9000))
    srv_parser.add_argument("--auth-key", type=str, required=True, help="Shared authentication secret key")
    srv_parser.add_argument("--secret-key", type=str, required=True, help="AES Encryption key / passphrase")
    srv_parser.add_argument("--out-dir", type=str, default=config.get("received_files_dir", "received_files"))

    # Send command
    send_parser = subparsers.add_parser("send", help="Send encrypted file to server")
    send_parser.add_argument("--file", type=str, required=True, help="File to encrypt and transfer")
    send_parser.add_argument("--host", type=str, default=config.get("default_host", "127.0.0.1"))
    send_parser.add_argument("--port", type=int, default=config.get("default_port", 9000))
    send_parser.add_argument("--auth-key", type=str, required=True, help="Shared authentication secret key")
    send_parser.add_argument("--secret-key", type=str, required=True, help="AES Encryption key / passphrase")

    args = parser.parse_args()

    app_name = args.name
    if args.name != default_app_name:
        config["app_name"] = args.name
        save_config(config)

    if args.command == "keygen":
        print(f"Generated Key: {CryptoUtils.generate_key()}")
    elif args.command == "history":
        display_history(config)
    elif args.command == "server":
        print_banner(app_name)
        srv = SecureTransferServer(args.host, args.port, args.auth_key, args.secret_key, args.out_dir, config.get("history_file", "transfer_history.json"))
        srv.start()
    elif args.command == "send":
        print_banner(app_name)
        client = SecureTransferClient(args.host, args.port, args.auth_key, args.secret_key, config.get("history_file", "transfer_history.json"))
        client.send_file(args.file)
    else:
        interactive_mode(app_name)

if __name__ == "__main__":
    main()
