# Secure File Transfer System (Terminal Version)

A terminal-based secure file transfer application featuring end-to-end AES encryption, mutual HMAC challenge-response sender/receiver authentication, SHA-256 integrity verification, and persistent transfer history logging.

---

## 📌 Overview & Purpose

The **Secure File Transfer System** enables safe, encrypted file transmission over network connections (TCP/IP sockets). Before transmission, files are encrypted using symmetric key cryptography (AES-256 / Fernet with PBKDF2 key derivation). Receiver and sender authenticate each other via a secret challenge-response protocol. Upon arrival, the system decrypts the file, recalculates the SHA-256 hash, and verifies integrity before saving.

---

## ✨ Features

- **End-to-End File Encryption & Decryption**:
  - Uses standard symmetric key cryptography (AES-128-CBC + HMAC-SHA256 Fernet or PBKDF2 derived keys).
  - Protects raw files from eavesdropping, interception, or unauthorized access during transfer.
- **Mutual Sender & Receiver Authentication**:
  - Challenge-response handshake protocol using secret shared authentication keys and HMAC-SHA256 nonces.
  - Automatically rejects unauthenticated or unauthorized clients before accepting file data.
- **SHA-256 File Integrity Verification**:
  - Computes pre-encryption checksums on the sender side and compares them against post-decryption checksums on the receiver side.
  - Detects payload tampering, network corruption, or incomplete transfers.
- **Persistent Transfer Logging**:
  - Records all transfer activities, metadata, file sizes, SHA-256 checksums, timestamps, and status to `transfer_history.json`.
- **Local Encryption/Decryption Helper**:
  - Standalone utility to encrypt or decrypt files locally without running a server.
- **Cryptographic Key Generator**:
  - Built-in generator (`keygen`) to produce random URL-safe 32-byte Fernet base64 keys.
- **Customizable Application Name**:
  - Configurable via command-line flags (`-n` / `--name`), interactive settings, or `config.json`.

---

## 📁 Project Structure

```text
Secure-File-Transfer-System/
├── main.py                    # Terminal runner & interactive menu
├── transfer_server.py         # TCP socket server for receiving encrypted files
├── transfer_client.py         # TCP socket client for sending encrypted files
├── crypto_utils.py            # AES encryption, decryption, key derivation & hashing
├── auth_utils.py              # HMAC challenge-response authentication protocol
├── history_logger.py          # Persistent transfer log manager
├── config.json                # Configuration file (host, port, app name)
├── README.md                  # Detailed documentation
└── tests/
    └── test_file_transfer.py  # Automated unit & end-to-end socket tests
```

---

## ⚙️ Prerequisites & Setup

- **Python Version**: Python 3.8+
- **Dependencies**: `cryptography`

### Quick Setup:
```bash
# 1. Navigate to project directory
cd Secure-File-Transfer-System

# 2. (Optional) Create and activate virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate

# 3. Install required package
python -m pip install cryptography
```

---

## 🚀 Terminal Deployment & Execution Guide

### Option 1: Direct Terminal Execution (Foreground)

#### Step A: Launch Receiver Server Terminal
Open Terminal #1 and run:
```bash
python main.py server --host 127.0.0.1 --port 9000 --auth-key MY_AUTH_KEY --secret-key MY_SECRET_KEY --out-dir received_files
```

#### Step B: Send Encrypted File from Client Terminal
Open Terminal #2 and run:
```bash
python main.py send --file confidential.txt --host 127.0.0.1 --port 9000 --auth-key MY_AUTH_KEY --secret-key MY_SECRET_KEY
```

---

### Option 2: Deploy Receiver Server as a Background Daemon Process

To keep the receiver server running persistently in the background:

#### On Windows (PowerShell Background Job):
```powershell
Start-Job -Name "SecureTransferServer" -ScriptBlock {
    python "C:\Users\HP\Desktop\Google Projects\Secure-File-Transfer-System\main.py" server --host 0.0.0.0 --port 9000 --auth-key "MY_AUTH_KEY" --secret-key "MY_SECRET_KEY"
}

# Check background server job status:
Get-Job -Name "SecureTransferServer"
```

#### On Linux / macOS (Nohup / Background Process):
```bash
nohup python3 main.py server --host 0.0.0.0 --port 9000 --auth-key "MY_AUTH_KEY" --secret-key "MY_SECRET_KEY" > server.log 2>&1 &

# Verify server process is listening:
netstat -tuln | grep 9000
```

---

### Option 3: Deploy as Global Terminal Commands

#### On Windows (PowerShell Alias):
Add to your `$PROFILE`:
```powershell
Function secure-send { python "C:\Users\HP\Desktop\Google Projects\Secure-File-Transfer-System\main.py" send $args }
Function secure-server { python "C:\Users\HP\Desktop\Google Projects\Secure-File-Transfer-System\main.py" server $args }
```
Now send files directly from any terminal prompt:
```powershell
secure-send --file report.pdf --auth-key MY_AUTH_KEY --secret-key MY_SECRET_KEY
```

#### On Linux / macOS (Bash / Zsh Alias):
```bash
alias secure-send='python3 "/path/to/Secure-File-Transfer-System/main.py" send'
alias secure-server='python3 "/path/to/Secure-File-Transfer-System/main.py" server'
```

---

## 🧪 Running Unit & Integration Tests

Run automated tests (including crypto verification, HMAC authentication, and full client-server socket transmission):
```bash
python -m unittest discover -s tests
```
