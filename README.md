# Learning Guide: Cybersecurity & Networking Projects

Welcome to the Learning Guide for the **File Integrity Checker**, **URL Safety Checker**, and **Secure File Transfer System**. The following document breaks down the fundamental computer science concepts, cybersecurity principles, software engineering architecture, and practical skills by studying and working with these three codebase implementations.

---

## 📚 Executive Summary of What You Will Learn

| Project | Core Computer Science Focus | Cybersecurity Domain | Key Python Concepts |
| :--- | :--- | :--- | :--- |
| **1. File Integrity Checker** | Cryptographic Hashing, State Auditing | Tamper Detection & System Baseline Monitoring | Stream Processing, JSON Manifests, `hashlib`, `argparse` |
| **2. URL Safety Checker** | URL Parsing, Heuristic Risk Scoring Engine | Phishing Detection, Network Reconnaissance & SSL Inspection | Regular Expressions, `urllib.parse`, `ssl`, `socket` |
| **3. Secure File Transfer System** | TCP Socket Client-Server Architecture | End-to-End Encryption, HMAC Challenge-Response Auth | `cryptography` (AES/Fernet), Threading, `hmac`, Socket Protocols |

---

## 🛠️ Project 1: File Integrity Checker

### 🎯 Key Learning Outcomes

1. **Cryptographic Hashing Fundamentals**:
   - Understand the difference between collision-resistant algorithms (**SHA-256**, **SHA-512**) and legacy/faster algorithms (**MD5**, **SHA-1**).
   - Learn why cryptographic hashes are one-way deterministic mathematical functions used to generate unique "digital fingerprints" for files.

2. **Memory-Efficient Stream Reading**:
   - Master loading large files (e.g., 5GB+) into memory safely using fixed-size byte buffers (64KB chunks) with `f.read(buffer_size)` instead of reading entire files into RAM at once.

3. **System Baseline Manifests & Delta Audit Analysis**:
   - Learn how tools like Tripwire, OSSEC, or Git track filesystem changes.
   - Understand baseline creation (scanning directory trees, recording relative paths, file sizes, modification timestamps, and checksums).
   - Learn how set operations and mapping checks detect file statuses:
     - **Intact**: Hash matches baseline manifest.
     - **Modified**: File exists but hash differs from baseline.
     - **Deleted**: Present in baseline manifest but missing on disk.
     - **Added**: Newly discovered file not present in baseline manifest.

---

## 🌐 Project 2: URL Safety Checker

### 🎯 Key Learning Outcomes

1. **URL Structure & RFC Protocol Parsing**:
   - Learn how URLs are decomposed according to RFC standards into:
     - `Scheme` (`http`, `https`)
     - `Netloc` / `Hostname` (`subdomain.domain.com`)
     - `Port` (`:80`, `:443`, `:8080`)
     - `Path` (`/account/login.php`)
     - `Query Strings` (`?user=123&verify=true`)

2. **Cybersecurity Phishing & Threat Heuristics**:
   - Learn common social engineering techniques used by attackers:
     - **IP Hostname Obfuscation**: Using raw IP addresses (`http://192.168.1.1/login`) instead of registered domains.
     - **Credential Spoofing**: Injecting `@` symbols into netloc string to obscure destination hostnames.
     - **Typosquatting & Homograph Attacks**: Character substitutions like `g00gle.com` or `paypa1.com`.
     - **High-Risk TLDs & Shorteners**: Identifying suspicious Top Level Domains (`.xyz`, `.top`, `.click`, `.zip`) and URL shortener services (`bit.ly`, `tinyurl.com`).
     - **Executable Path Extensions**: Catching double file extensions (`document.pdf.exe`).

3. **Weighted Risk Scoring Systems**:
   - Learn how to implement heuristic algorithms that aggregate weighted point deductions to compute normalized Risk Scores (0–100) and map them to risk levels (**SAFE**, **LOW RISK**, **SUSPICIOUS**).

4. **Network Socket & SSL/TLS Handshake Inspection**:
   - Learn how to use Python's native `ssl` and `socket` modules to establish TLS handshakes, extract peer X.509 certificates, and inspect Issuer Common Names and Certificate Authority trust chains.

---

## 🔐 Project 3: Secure File Transfer System

### 🎯 Key Learning Outcomes

1. **Applied Cryptography & Data Encryption**:
   - Master **Symmetric Cryptography**: Encrypting and decrypting data using AES-128-CBC / AES-256 Fernet constructs.
   - Learn **Key Derivation Functions (KDF)**: Converting user passphrases into cryptographically strong 256-bit keys using **PBKDF2-HMAC-SHA256** with salt iterations.

2. **Network Protocol Design & Mutual Authentication**:
   - Learn how to build custom application-level protocols over TCP sockets.
   - Master **Challenge-Response Authentication**:
     - Server generates random 32-byte nonce (`urandom`).
     - Client computes HMAC-SHA256 hash using shared secret.
     - Server verifies HMAC match before granting access. This prevents eavesdropping and replay attacks.

3. **End-to-End Data Integrity & Tamper Verification**:
   - Implement multi-stage integrity checks:
     1. Sender computes pre-transfer SHA-256 checksum.
     2. Sender encrypts file and streams payload.
     3. Receiver decrypts payload and computes post-transfer SHA-256 checksum.
     4. Receiver verifies original checksum matches decrypted checksum before saving file.

4. **Network Socket Programming & Threading**:
   - Learn TCP socket lifecycle: `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `sendall()`, `recv()`, `close()`.
   - Learn non-blocking daemon server execution and multi-threaded connection handling.

5. **Audit Logging & Transaction History**:
   - Learn persistent history logging (`transfer_history.json`) for forensic accountability, tracking timestamps, peer IP addresses, action types, file hashes, and transfer outcome statuses.

---

## 🏗️ Core Software Engineering Principles Demonstrated

Beyond domain knowledge, studying these three codebases teaches professional software development practices:

1. **Modular Architecture & Separation of Concerns**:
   - Core logic is isolated in dedicated modules (`integrity_checker.py`, `url_checker.py`, `crypto_utils.py`, `auth_utils.py`), decoupled from CLI user interfaces (`main.py`).

2. **Flexible User Interface Design**:
   - Supports both non-blocking **Command Line Interface (CLI)** flags (for scripting/automation) and **Interactive Terminal Menus** (for user-friendly manual operation).

3. **External Configuration Management**:
   - Uses `config.json` files to manage configurable parameters (application titles, default ports, default algorithms, keyword lists) without modifying source code.

4. **Automated Testing & Continuous Integration**:
   - Every project includes unit tests using Python's standard `unittest` framework, validating logic, edge cases, and end-to-end socket communications.

---

## 💡 Recommended Next Exercises to Extend Your Learning

To challenge yourself and deepen your understanding, try adding these enhancements:

1. **File Integrity Checker**:
   - Add support for recursive directory exclusions (e.g., ignoring `.git/` or `node_modules/`).
   - Add real-time filesystem watching using file notification events (`watchdog`).

2. **URL Safety Checker**:
   - Integrate an external Threat Intelligence API (like VirusTotal or Google Safe Browsing API) to combine offline heuristics with live global threat databases.

3. **Secure File Transfer System**:
   - Upgrade the TCP socket layer to use TLS/SSL certificates (`ssl.wrap_socket`) for encrypted transport layer security alongside message payload encryption.
   - Implement multi-part parallel file chunking for resume capability on interrupted transfers.
