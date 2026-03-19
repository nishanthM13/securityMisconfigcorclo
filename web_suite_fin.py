#!/usr/bin/env python3
"""
web_vuln_suite.py

Unified launcher for your 3 CLI scanners:

1) CORS Misconfiguration Scanner      -> cors.py
2) S3 Bucket Misconfiguration Scanner -> dsb.py
3) OAuth/OIDC Misconfiguration Scanner-> oauth_vuln_scanner.py

Run this file, pick an option, answer a couple of prompts, and it will
invoke the appropriate tool with sensible default arguments.
"""

import subprocess
import sys


# ---------------------------
# 1) CORS scanner launcher
# ---------------------------
def run_cors_scanner():
    print("\n[+] CORS Misconfiguration Scanner selected.")
    target = input(
        "Enter target URL (e.g. http://127.0.0.1:5000/cors/reflect): "
    ).strip()
    if not target:
        print("[-] No target URL provided, returning to menu.")
        return

    origin = input(
        "Enter Origin to test (default: https://evil.attacker.com): "
    ).strip()
    if not origin:
        origin = "https://evil.attacker.com"

    extra = input("Use two-origin reflection test? (y/N): ").strip().lower()
    two_origin_flag = "--two-origin" if extra == "y" else ""

    cmd = ["python3", "cors.py", target, "--origin", origin]
    if two_origin_flag:
        cmd.append(two_origin_flag)

    print("\n[+] Running:", " ".join(cmd), "\n")
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print("[-] Could not find cors.py. Make sure it is in the same directory.")


# ---------------------------
# 2) S3 scanner launcher
#     (ONLY single-bucket mode)
# ---------------------------
def run_s3_scanner():
    print("\n[+] S3 Bucket Misconfiguration Scanner selected.")
    # Only one mode now: scan a single bucket name
    bucket = input("Enter S3 bucket name (e.g. my-bucket-name): ").strip()
    if not bucket:
        print("[-] No bucket given, returning to menu.")
        return

    base_cmd = ["python3", "dsb.py", "-b", bucket]

    write_test = input(
        "Enable public write test? (ONLY in your own lab!) (y/N): "
    ).strip().lower()
    if write_test == "y":
        base_cmd.append("--test-write")

    print("\n[+] Running:", " ".join(base_cmd), "\n")
    try:
        subprocess.run(base_cmd, check=False)
    except FileNotFoundError:
        print("[-] Could not find dsb.py. Make sure it is in the same directory.")


# ---------------------------
# 3) OAuth/OIDC scanner launcher
# ---------------------------
def run_oauth_scanner():
    print("\n[+] OAuth/OIDC Misconfiguration Scanner selected.")
    target = input(
        "Enter target base URL or host (e.g. http://127.0.0.1:8000): "
    ).strip()
    if not target:
        print("[-] No target provided, returning to menu.")
        return

    fast = input("Use fast mode? (y/N): ").strip().lower()
    insecure = input(
        "Disable TLS verification (insecure)? (n recommended) (y/N): "
    ).strip().lower()
    out_file = input("Optional: output JSON file path (or leave empty): ").strip()

    cmd = ["python3", "oauth_vuln_scanner.py", target]

    if fast == "y":
        cmd.append("--fast")
    if insecure == "y":
        cmd.append("--insecure")
    if out_file:
        cmd.extend(["-o", out_file])

    print("\n[+] Running:", " ".join(cmd), "\n")
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print("[-] Could not find oauth_vuln_scanner.py. "
              "Make sure it is in the same directory.")


# ---------------------------
# Main menu
# ---------------------------
def main():
    while True:
        print("\n============================================")
        print("  Web Misconfiguration Scanner Suite")
        print("============================================")
        print("1) CORS Misconfiguration Scanner")
        print("2) S3 Bucket Misconfiguration Scanner")
        print("3) OAuth/OIDC Misconfiguration Scanner")
        print("q) Quit\n")

        choice = input("Select an option (1/2/3/q): ").strip().lower()

        if choice == "1":
            run_cors_scanner()
        elif choice == "2":
            run_s3_scanner()
        elif choice == "3":
            run_oauth_scanner()
        elif choice in ("q", "quit", "exit"):
            print("[*] Exiting. Bye.")
            sys.exit(0)
        else:
            print("[-] Invalid choice, try again.\n")


if __name__ == "__main__":
    main()
