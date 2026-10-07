# URL Safety Checker

A terminal-based security tool to analyze target web URLs, validate URL syntax, enforce HTTPS protocol compliance, detect phishing keywords, identify high-risk TLDs and typosquatting domain patterns, and assign a comprehensive Risk Score.

---

## 📌 Overview & Purpose

The **URL Safety Checker** protects users from phishing websites, credential harvesting scams, malicious URLs, and insecure web connections. It analyzes URL components (scheme, domain, subdomains, port, path, query parameters) against multiple security heuristic rules and optionally performs live SSL certificate checks.

---

## ✨ Features

- **URL Input & Format Validation**:
  - Validates syntax and parses protocol schemes, hostnames, ports, and paths.
  - Detects IP address hostnames (e.g. `http://192.168.1.1/login`).
  - Detects credential spoofing `@` symbols in URLs.
  - Flags excessive subdomain levels (> 3 subdomains).
- **HTTPS Enforcement Check**:
  - Identifies insecure `http://` or non-standard protocol usage.
- **Phishing & Suspicious Keyword Identification**:
  - Scans for sensitive target keywords (`login`, `signin`, `verify`, `account`, `banking`, `paypal`, `wallet`, `claim`, `bonus`, `crypto`, `billing`, etc.).
  - Detects executable/suspicious file paths (e.g. `.exe`, `.apk`, `.vbs`, `.bat`, `.cmd`).
- **Domain & TLD Risk Analysis**:
  - Identifies high-risk Top Level Domains (`.xyz`, `.top`, `.tk`, `.zip`, `.click`, `.work`, `.link`).
  - Detects URL shortener services (`bit.ly`, `tinyurl.com`, `t.co`, `ow.ly`).
- **Typosquatting & Brand Impersonation**:
  - Detects common character-substitution typosquatting patterns (e.g. `g00gle`, `paypa1`, `m[i1]cr[0o]s[0o]ft`).
- **Live SSL Certificate Inspection**:
  - Performs optional TCP/TLS socket handshakes to inspect SSL certificate validity, subject CN, and issuing authority.
- **Risk Score & Classification**:
  - Computes a cumulative Risk Score (0 - 100) and displays clear terminal results:
    - **[SAFE]** (Risk score < 20)
    - **[LOW TO MEDIUM RISK]** (Risk score 20 - 49)
    - **[SUSPICIOUS]** (Risk score ≥ 50)
- **Customizable Application Name**: Configure app name via `-n` / `--name` flag, interactive settings, or `config.json`.

---

## 📁 Project Structure

```text
URL-Safety-Checker/
├── main.py                 # Terminal runner & interactive menu
├── url_checker.py          # Core heuristic engine & SSL checker
├── config.json             # Configuration file (keywords, TLDs, app name)
├── README.md               # Detailed documentation
└── tests/
    └── test_url_checker.py # Automated unit tests
```

---

## ⚙️ Prerequisites & Setup

- **Python Version**: Python 3.8+ (Uses standard Python library).

### Quick Setup:
```bash
# 1. Navigate to project directory
cd URL-Safety-Checker

# 2. (Optional) Create and activate virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Linux / macOS:
source venv/bin/activate
```

---

## 🚀 Terminal Deployment & Execution Guide

### Option 1: Direct Local Terminal Execution

Run interactively:
```bash
python main.py
```

Run CLI single commands:
```bash
# Analyze a Single URL
python main.py -u "https://www.google.com"

# Analyze a Suspicious URL with Live SSL Certificate Check
python main.py -u "http://192.168.1.100/paypal-update-login/verify.php" --ssl

# Batch Analyze URLs from a Text File
python main.py -f urls.txt
```

---

### Option 2: Deploy as a Global Terminal Shortcut / Command

To run `url-check` from **any terminal location**:

#### On Windows (PowerShell):
Add to your `$PROFILE`:
```powershell
Function url-check { python "C:\Users\HP\Desktop\Google Projects\URL-Safety-Checker\main.py" $args }
```
Now you can type anywhere:
```powershell
url-check -u "https://example.xyz/login"
```

#### On Windows (CMD / Batch Script):
Create a file `urlcheck.bat` in a folder on your system `PATH`:
```cmd
@echo off
python "C:\Users\HP\Desktop\Google Projects\URL-Safety-Checker\main.py" %*
```

#### On Linux / macOS (Bash / Zsh):
Add an alias to `~/.bashrc` or `~/.zshrc`:
```bash
alias url-check='python3 "/path/to/Google Projects/URL-Safety-Checker/main.py"'
```

---

### Option 3: Deploy for Automated Batch URL Auditing

Integrate into shell scripts to automatically filter unsafe URLs from access logs or incoming link lists:
```bash
# Scan links in batch and pipe results to log file
python main.py -f suspicious_links.txt > url_audit_report.txt
```

---

## 🧪 Running Unit Tests

Run unit tests to verify URL parsing, keyword detection, HTTPS enforcement, and risk scoring:
```bash
python -m unittest discover -s tests
```
