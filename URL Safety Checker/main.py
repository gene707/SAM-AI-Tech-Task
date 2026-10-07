import argparse
import sys
import os
import json
from url_checker import URLSafetyChecker

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"app_name": "URL Safety Checker"}

def save_config(config):
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

def print_banner(app_name):
    border = "=" * (len(app_name) + 12)
    print(f"\n{border}")
    print(f"  [>] {app_name}  ")
    print(f"{border}\n")

def display_report(result: dict):
    print("\n=================== URL SAFETY REPORT ===================")
    print(f"Target URL   : {result['url']}")
    
    if not result.get("is_valid_format"):
        print(f"Format Status: INVALID FORMAT ({result.get('format_message')})")
        print("RESULT       : [INVALID / DANGEROUS]")
        print("========================================================\n")
        return

    print(f"Domain       : {result.get('domain')}")
    print(f"HTTPS Status : {'[OK] HTTPS Enabled' if result.get('is_https') else '[WARN] HTTP Insecure (No HTTPS)'}")
    print(f"Risk Score   : {result.get('risk_score')} / 100")
    
    status = result.get("status")
    if status == "SAFE":
        print("RESULT       : [SAFE] - No significant security risks detected.")
    elif status == "LOW_TO_MEDIUM_RISK":
        print("RESULT       : [LOW TO MEDIUM RISK] - Exercise caution when visiting.")
    else:
        print("RESULT       : [SUSPICIOUS] - High risk indicators found!")
        
    print("\n--- Key Heuristic Findings ---")
    for f in result.get("findings", []):
        pt_str = f"+{f['risk_points']} pts" if f['risk_points'] > 0 else "OK"
        print(f" [{pt_str:<6}] {f['rule']}: {f['detail']}")

    if result.get("ssl_info"):
        ssl_data = result["ssl_info"]
        print("\n--- Live SSL Certificate Status ---")
        if ssl_data.get("verified"):
            print(f" SSL Certificate Verified: Subject CN = {ssl_data.get('subject_cn')}, Issuer = {ssl_data.get('issuer_org')}")
        else:
            print(f" SSL Handshake Failed/Incomplete: {ssl_data.get('error')}")

    print("========================================================\n")

def interactive_mode(app_name):
    config = load_config()
    current_name = app_name or config.get("app_name", "URL Safety Checker")
    checker = URLSafetyChecker(
        custom_keywords=config.get("suspicious_keywords"),
        custom_tlds=config.get("suspicious_tlds")
    )
    
    while True:
        print_banner(current_name)
        print("Select an option:")
        print("1. Check single URL safety")
        print("2. Batch check URLs from a text file")
        print("3. Check single URL with Live SSL Certificate test")
        print("4. Change Application Name (Current: '{}')".format(current_name))
        print("0. Exit")

        choice = input("\nEnter choice (0-4): ").strip()

        if choice == "1":
            url = input("\nEnter URL to analyze: ").strip()
            if url:
                res = checker.analyze_url(url, perform_live_ssl=False)
                display_report(res)
            else:
                print("[!] URL cannot be empty.")

        elif choice == "2":
            file_path = input("\nEnter path to file containing URLs (one per line): ").strip('"\' ')
            if not os.path.exists(file_path):
                print(f"[ERR] File not found: {file_path}")
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip()]
                print(f"\nScanning {len(urls)} URLs from '{file_path}'...\n")
                for u in urls:
                    res = checker.analyze_url(u)
                    display_report(res)
            except Exception as e:
                print(f"[ERR] Failed to read batch file: {e}")

        elif choice == "3":
            url = input("\nEnter HTTPS URL to test with Live SSL: ").strip()
            if url:
                print("\nAttempting live connection and analyzing URL...")
                res = checker.analyze_url(url, perform_live_ssl=True)
                display_report(res)

        elif choice == "4":
            new_name = input(f"Enter new application name [current: '{current_name}']: ").strip()
            if new_name:
                current_name = new_name
                config["app_name"] = new_name
                save_config(config)
                print(f"\n[SUCCESS] Application name updated to '{current_name}'.")

        elif choice == "0":
            print("\nExiting URL Safety Checker. Goodbye!")
            sys.exit(0)
        else:
            print("[!] Invalid choice.")

def main():
    config = load_config()
    default_app_name = config.get("app_name", "URL Safety Checker")

    parser = argparse.ArgumentParser(description="Terminal URL Safety Checker")
    parser.add_argument("-n", "--name", type=str, default=default_app_name, help="Set custom application name")
    parser.add_argument("-u", "--url", type=str, help="Single URL to analyze")
    parser.add_argument("-f", "--file", type=str, help="Text file with URLs to analyze in batch")
    parser.add_argument("--ssl", action="store_true", help="Perform live SSL certificate check")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive menu mode")

    args = parser.parse_args()

    app_name = args.name
    if args.name != default_app_name:
        config["app_name"] = args.name
        save_config(config)

    checker = URLSafetyChecker(
        custom_keywords=config.get("suspicious_keywords"),
        custom_tlds=config.get("suspicious_tlds")
    )

    if args.url:
        print_banner(app_name)
        res = checker.analyze_url(args.url, perform_live_ssl=args.ssl)
        display_report(res)
    elif args.file:
        print_banner(app_name)
        if os.path.exists(args.file):
            with open(args.file, "r", encoding="utf-8") as f:
                urls = [l.strip() for l in f if l.strip()]
            for u in urls:
                res = checker.analyze_url(u, perform_live_ssl=args.ssl)
                display_report(res)
        else:
            print(f"Error: File not found: {args.file}")
    else:
        interactive_mode(app_name)

if __name__ == "__main__":
    main()
