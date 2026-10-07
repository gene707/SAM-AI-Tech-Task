import argparse
import sys
import os
import json
from integrity_checker import HashCalculator, HashComparator, BaselineManager

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"app_name": "File Integrity Checker", "default_algorithm": "sha256", "baseline_file": "baseline_manifest.json"}

def save_config(config):
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def print_banner(app_name):
    border = "=" * (len(app_name) + 12)
    print(f"\n{border}")
    print(f"  [>] {app_name}  ")
    print(f"{border}\n")

def interactive_mode(app_name):
    config = load_config()
    current_name = app_name or config.get("app_name", "File Integrity Checker")
    
    while True:
        print_banner(current_name)
        print("Select an option:")
        print("1. Calculate file hash (SHA-256 / MD5 / SHA-512 / SHA-1)")
        print("2. Compare file with expected hash")
        print("3. Compare two files")
        print("4. Generate baseline hash manifest for a directory")
        print("5. Verify directory integrity against baseline manifest")
        print("6. Change Application Name (Current: '{}')".format(current_name))
        print("0. Exit")
        
        choice = input("\nEnter choice (0-6): ").strip()
        
        if choice == "1":
            path_input = input("Enter file path or multiple paths separated by comma: ").strip()
            paths = [p.strip('"\' ') for p in path_input.split(",") if p.strip()]
            algo = input("Enter algorithm (sha256/md5/sha512/sha1) [default: sha256]: ").strip().lower() or "sha256"
            print("\n--- Hash Calculation Results ---")
            for path in paths:
                if not os.path.exists(path):
                    print(f"[ERR] File not found: {path}")
                    continue
                try:
                    file_hash = HashCalculator.calculate_hash(path, algo)
                    print(f"File: {path}")
                    print(f"Algo: {algo.upper()}")
                    print(f"Hash: {file_hash}\n")
                except Exception as e:
                    print(f"[ERR] {path}: {e}\n")
                    
        elif choice == "2":
            file_path = input("Enter file path: ").strip('"\' ')
            expected_hash = input("Enter expected hash string: ").strip()
            algo = input("Enter algorithm (sha256/md5/sha512/sha1) [default: sha256]: ").strip().lower() or "sha256"
            try:
                match, actual_hash, _ = HashComparator.compare_file_with_hash(file_path, expected_hash, algo)
                print("\n--- Integrity Hash Comparison ---")
                print(f"File: {file_path}")
                print(f"Actual Hash:   {actual_hash}")
                print(f"Expected Hash: {expected_hash.lower()}")
                if match:
                    print("\n[SUCCESS] STATUS: MATCH! File integrity is verified intact.")
                else:
                    print("\n[WARNING] STATUS: MISMATCH! File has been altered or hash is invalid.")
            except Exception as e:
                print(f"[ERR] Comparison failed: {e}")

        elif choice == "3":
            file1 = input("Enter first file path: ").strip('"\' ')
            file2 = input("Enter second file path: ").strip('"\' ')
            algo = input("Enter algorithm (sha256/md5/sha512/sha1) [default: sha256]: ").strip().lower() or "sha256"
            try:
                match, hash1, hash2 = HashComparator.compare_two_files(file1, file2, algo)
                print("\n--- Two-File Hash Comparison ---")
                print(f"File 1: {file1} -> {hash1}")
                print(f"File 2: {file2} -> {hash2}")
                if match:
                    print("\n[SUCCESS] STATUS: MATCH! Files are identical.")
                else:
                    print("\n[WARNING] STATUS: MISMATCH! Files differ.")
            except Exception as e:
                print(f"[ERR] Comparison failed: {e}")

        elif choice == "4":
            target_dir = input("Enter directory path to scan: ").strip('"\' ')
            if not os.path.isdir(target_dir):
                print(f"[ERR] Invalid directory: {target_dir}")
                continue
            out_file = input("Enter manifest file output name [default: baseline_manifest.json]: ").strip() or "baseline_manifest.json"
            algo = input("Enter algorithm (sha256/md5/sha512) [default: sha256]: ").strip().lower() or "sha256"
            try:
                mgr = BaselineManager(target_dir, algo)
                res = mgr.generate_baseline(out_file)
                print(f"\n[SUCCESS] Baseline manifest generated with {res['total_files']} files saved to '{out_file}'.")
            except Exception as e:
                print(f"[ERR] Failed to generate baseline: {e}")

        elif choice == "5":
            target_dir = input("Enter directory path to verify: ").strip('"\' ')
            if not os.path.isdir(target_dir):
                print(f"[ERR] Invalid directory: {target_dir}")
                continue
            manifest_file = input("Enter baseline manifest file path [default: baseline_manifest.json]: ").strip() or "baseline_manifest.json"
            try:
                mgr = BaselineManager(target_dir)
                res = mgr.verify_baseline(manifest_file)
                summary = res["summary"]
                print("\n================ VERIFICATION REPORT ================")
                print(f"Target Directory : {res['target_dir']}")
                print(f"Algorithm Used   : {res['algorithm'].upper()}")
                print(f"Total Checked    : {summary['total_checked']}")
                print(f"Intact Files     : {summary['intact']}")
                print(f"Modified Files   : {summary['modified']}")
                print(f"Deleted Files    : {summary['deleted']}")
                print(f"Added Files      : {summary['added']}")
                print("----------------------------------------------------")
                
                if res["modified"]:
                    print("\n[!] MODIFIED FILES:")
                    for item in res["modified"]:
                        print(f"  - {item['path']} (Expected: {item.get('expected_hash')[:10]}... | Actual: {item.get('actual_hash')[:10]}...)")
                if res["deleted"]:
                    print("\n[!] DELETED FILES:")
                    for item in res["deleted"]:
                        print(f"  - {item['path']}")
                if res["added"]:
                    print("\n[+] NEWLY ADDED FILES:")
                    for item in res["added"]:
                        print(f"  + {item['path']}")
                        
                if summary['modified'] == 0 and summary['deleted'] == 0:
                    print("\n[SUCCESS] INTEGRITY STATUS: OK! No unexpected modifications detected.")
                else:
                    print("\n[WARNING] INTEGRITY STATUS: MODIFIED! Potential integrity breach or changes detected.")
            except Exception as e:
                print(f"[ERR] Verification failed: {e}")

        elif choice == "6":
            new_name = input(f"Enter new application name [current: '{current_name}']: ").strip()
            if new_name:
                current_name = new_name
                config["app_name"] = new_name
                save_config(config)
                print(f"\n[SUCCESS] Application name updated to '{current_name}'.")

        elif choice == "0":
            print("\nExiting File Integrity Checker. Goodbye!")
            sys.exit(0)
        else:
            print("[!] Invalid option. Please enter a number between 0 and 6.")

def main():
    config = load_config()
    default_app_name = config.get("app_name", "File Integrity Checker")
    
    parser = argparse.ArgumentParser(description="Terminal File Integrity Checker")
    parser.add_argument("-n", "--name", type=str, default=default_app_name, help="Set custom application title name")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive terminal mode")
    parser.add_argument("--hash", nargs="+", help="Calculate hash for one or more files")
    parser.add_argument("--algo", type=str, default="sha256", choices=["sha256", "md5", "sha512", "sha1"], help="Hash algorithm")
    parser.add_argument("--compare-files", nargs=2, metavar=("FILE1", "FILE2"), help="Compare hashes of two files")
    parser.add_argument("--compare-hash", nargs=2, metavar=("FILE", "EXPECTED_HASH"), help="Compare file hash with expected string")
    parser.add_argument("--create-baseline", type=str, help="Directory to create baseline manifest for")
    parser.add_argument("--verify-baseline", type=str, help="Directory to verify against baseline manifest")
    parser.add_argument("--manifest", type=str, default="baseline_manifest.json", help="Manifest file path")

    args = parser.parse_args()

    app_name = args.name
    if args.name != default_app_name:
        config["app_name"] = args.name
        save_config(config)

    if args.hash:
        print_banner(app_name)
        for f in args.hash:
            try:
                h = HashCalculator.calculate_hash(f, args.algo)
                print(f"File: {f}\nAlgo: {args.algo.upper()}\nHash: {h}\n")
            except Exception as e:
                print(f"Error checking {f}: {e}")
    elif args.compare_files:
        print_banner(app_name)
        file1, file2 = args.compare_files
        match, h1, h2 = HashComparator.compare_two_files(file1, file2, args.algo)
        print(f"File 1: {file1} -> {h1}")
        print(f"File 2: {file2} -> {h2}")
        print("Status: MATCH!" if match else "Status: MISMATCH!")
    elif args.compare_hash:
        print_banner(app_name)
        file_path, expected = args.compare_hash
        match, actual, _ = HashComparator.compare_file_with_hash(file_path, expected, args.algo)
        print(f"File: {file_path}")
        print(f"Actual:   {actual}")
        print(f"Expected: {expected}")
        print("Status: MATCH!" if match else "Status: MISMATCH!")
    elif args.create_baseline:
        print_banner(app_name)
        mgr = BaselineManager(args.create_baseline, args.algo)
        res = mgr.generate_baseline(args.manifest)
        print(f"Baseline created with {res['total_files']} files saved to '{args.manifest}'.")
    elif args.verify_baseline:
        print_banner(app_name)
        mgr = BaselineManager(args.verify_baseline, args.algo)
        res = mgr.verify_baseline(args.manifest)
        s = res["summary"]
        print(f"Checked: {s['total_checked']} | Intact: {s['intact']} | Modified: {s['modified']} | Deleted: {s['deleted']} | Added: {s['added']}")
    else:
        interactive_mode(app_name)

if __name__ == "__main__":
    main()
