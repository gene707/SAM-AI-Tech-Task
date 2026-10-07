# File Integrity Checker

A robust, terminal-based security tool to calculate cryptographic file hashes, compare file checksums, generate baseline system manifests, and detect unauthorized file modifications across entire directories.

---

## 📌 Overview & Purpose

The **File Integrity Checker** allows users and administrators to monitor files for accidental corruption, unauthorized tampering, or unexpected system modifications. By utilizing cryptographic hashing algorithms (SHA-256, MD5, SHA-512, SHA-1), it establishes a trusted checksum baseline and continuously verifies file integrity against it.

---

## ✨ Features

- **Multi-Algorithm Hash Calculation**: Computes SHA-256, MD5, SHA-512, and SHA-1 hashes using memory-efficient 64KB chunked reading.
- **Hash Comparison**:
  - Compare a local file's hash against an expected hash string.
  - Compare two files directly to verify identical content.
- **Modification & Tamper Detection**:
  - Scans directories and generates a structured JSON baseline manifest containing paths, sizes, hashes, and timestamps.
  - Verifies live directories against baseline manifests to highlight **Intact**, **Modified**, **Deleted**, and **Newly Added** files.
- **Customizable Project Name**: Supports custom tool branding via command-line flags (`-n` / `--name`), interactive settings, or `config.json`.
- **Dual Operating Modes**:
  - **Interactive Terminal Menu**: Easy step-by-step terminal prompts.
  - **Command-Line Interface (CLI)**: Non-blocking single commands for automation and scripts.

---

## 📁 Project Structure

```text
File-Integrity-Checker/
├── main.py                # Terminal runner & interactive menu
├── integrity_checker.py   # Core hashing & baseline verification engine
├── config.json            # Configuration file (app name & defaults)
├── README.md              # Detailed documentation
└── tests/
    └── test_integrity.py  # Automated unit & integration tests
```

---

## ⚙️ Prerequisites & Setup

- **Python Version**: Python 3.8+ (Uses standard Python library).

### Quick Setup:
```bash
# 1. Navigate to project directory
cd File-Integrity-Checker

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
# Calculate Hash of a File
python main.py --hash sample.txt --algo sha256

# Compare Two Files
python main.py --compare-files file1.txt file2.txt

# Create Directory Baseline Manifest
python main.py --create-baseline ./my_folder --manifest baseline.json

# Verify Directory Integrity Against Baseline
python main.py --verify-baseline ./my_folder --manifest baseline.json
```

---

### Option 2: Deploy as a Global Terminal Shortcut / Command

To run `integrity-check` from **any directory** in your terminal without typing `python main.py`:

#### On Windows (PowerShell):
Add a PowerShell alias or function in your `$PROFILE`:
```powershell
# Run in PowerShell to add alias:
Function integrity-check { python "C:\Users\HP\Desktop\Google Projects\File-Integrity-Checker\main.py" $args }
```
Now you can type anywhere:
```powershell
integrity-check --verify-baseline C:\ImportantData
```

#### On Windows (CMD / Batch Script):
Create a file named `integrity.bat` in a folder included in your system `PATH`:
```cmd
@echo off
python "C:\Users\HP\Desktop\Google Projects\File-Integrity-Checker\main.py" %*
```

#### On Linux / macOS (Bash / Zsh):
Add an alias to `~/.bashrc` or `~/.zshrc`:
```bash
alias integrity-check='python3 "/path/to/Google Projects/File-Integrity-Checker/main.py"'
```

---

### Option 3: Deploy as an Automated Scheduled Background Job

#### On Windows Task Scheduler / PowerShell Background Job:
```powershell
Start-Job -ScriptBlock { python "C:\Users\HP\Desktop\Google Projects\File-Integrity-Checker\main.py" --verify-baseline "C:\ImportantData" }
```

#### On Linux (Cron Job for hourly integrity checks):
```cron
0 * * * * python3 /path/to/File-Integrity-Checker/main.py --verify-baseline /var/www/html --manifest /var/backups/baseline.json >> /var/log/integrity.log 2>&1
```

---

## 🧪 Running Unit Tests

Run automated tests to verify hash calculation, comparison, and baseline modification detection:
```bash
python -m unittest discover -s tests
```
