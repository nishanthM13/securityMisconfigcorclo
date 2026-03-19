#!/usr/bin/env python3
import argparse
import random
import re
import string
import sys
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 5

# ---------- helpers ----------

def random_name(length=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

def bucket_base_urls(bucket):
    # Virtual-hosted style is most common now
    return [
        f"https://{bucket}.s3.amazonaws.com",
        f"http://{bucket}.s3.amazonaws.com",
    ]

# ---------- S3 checks ----------

def check_exists(bucket):
    for base in bucket_base_urls(bucket):
        try:
            r = requests.head(base, timeout=TIMEOUT)
            if r.status_code in (200, 301, 302, 403):
                return True, r.status_code
            if r.status_code == 404:
                return False, 404
        except requests.RequestException:
            continue
    return False, None

def check_list(bucket):
    """Check if anonymous listing is allowed."""
    for base in bucket_base_urls(bucket):
        try:
            url = base + "/?list-type=2"
            r = requests.get(url, timeout=TIMEOUT)
            # 200 with XML ListBucketResult usually = listable
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                return True, r.text[:500]
            # 403 often means exists but no list permission
        except requests.RequestException:
            continue
    return False, None

def check_read_common_objects(bucket, common_names=None):
    if common_names is None:
        common_names = ["index.html", "index.htm", "logo.png", "robots.txt"]
    readable = []
    for name in common_names:
        for base in bucket_base_urls(bucket):
            try:
                url = urljoin(base + "/", name)
                r = requests.get(url, timeout=TIMEOUT)
                if r.status_code == 200:
                    readable.append((name, url, len(r.content)))
                    break
            except requests.RequestException:
                continue
    return readable

def check_write(bucket, do_write_test=False):
    """OPTIONAL destructive check – only if explicitly enabled."""
    if not do_write_test:
        return None, "write_check_disabled"

    test_name = f"bugbounty-test-{random_name()}.txt"
    body = b"bugbounty write test - remove me"

    for base in bucket_base_urls(bucket):
        url = urljoin(base + "/", test_name)
        try:
            put = requests.put(url, data=body, timeout=TIMEOUT)
            if put.status_code in (200, 201):
                # Try to delete to be nice
                try:
                    requests.delete(url, timeout=TIMEOUT)
                except requests.RequestException:
                    pass
                return True, f"Successfully wrote test object {test_name}"
            elif put.status_code in (403, 405):
                return False, f"Write forbidden ({put.status_code})"
        except requests.RequestException as e:
            return False, f"Error: {e}"
    return False, "Unknown / no reachable endpoint"

def classify(bucket_exists, listable, readable, write_result):
    if not bucket_exists:
        return "NOT_FOUND"

    write_vuln = write_result and write_result[0] is True
    if write_vuln:
        return "CRITICAL_PUBLIC_WRITE"

    if listable and len(readable) > 0:
        return "HIGH_LISTING_AND_READ"

    if listable:
        return "MEDIUM_LISTING"

    if len(readable) > 0:
        return "LOW_PUBLIC_READ"

    return "NO_OBVIOUS_ANON_ISSUE"

def scan_bucket(bucket, do_write_test=False):
    print(f"[*] Scanning bucket: {bucket}")

    exists, code = check_exists(bucket)
    print(f"    - Exists: {exists} (status={code})")

    if not exists:
        return {"bucket": bucket, "status": "NOT_FOUND"}

    listable, _ = check_list(bucket)
    print(f"    - Listable: {listable}")

    readable = check_read_common_objects(bucket)
    if readable:
        print("    - Publicly readable objects:")
        for name, url, size in readable:
            print(f"        {name} ({size} bytes) -> {url}")
    else:
        print("    - No common public objects found")

    write_vuln, write_info = check_write(bucket, do_write_test)
    print(f"    - Write check: {write_vuln} ({write_info})")

    severity = classify(exists, listable, readable, (write_vuln, write_info))

    return {
        "bucket": bucket,
        "exists": exists,
        "http_status": code,
        "listable": listable,
        "readable_objects": readable,
        "write_check": {"result": write_vuln, "info": write_info},
        "severity": severity,
    }

# ---------- Website → S3 discovery ----------

# Regexes to extract S3 buckets from any text/HTML/JS
S3_HOST_RE = re.compile(
    r"https?://([a-z0-9.\-]+)\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com",
    re.IGNORECASE,
)
S3_PATH_RE = re.compile(
    r"https?://s3(?:-[a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]+)/",
    re.IGNORECASE,
)
S3_WEBSITE_RE = re.compile(
    r"https?://([a-z0-9.\-]+)\.s3-website-[a-z0-9-]+\.amazonaws\.com",
    re.IGNORECASE,
)

def discover_buckets_in_text(text):
    buckets = set()

    for m in S3_HOST_RE.findall(text):
        buckets.add(m.strip().lower())

    for m in S3_PATH_RE.findall(text):
        buckets.add(m.strip().lower())

    for m in S3_WEBSITE_RE.findall(text):
        buckets.add(m.strip().lower())

    return buckets

def fetch_url(url):
    try:
        r = requests.get(url, timeout=TIMEOUT)
        return r.text, r.status_code
    except requests.RequestException as e:
        print(f"[-] Error fetching {url}: {e}")
        return None, None

def scan_website(url, do_write_test=False):
    print(f"[*] Fetching website: {url}")
    html, status = fetch_url(url)
    if html is None:
        return []

    print(f"    - HTTP status: {status}")

    # Basic origin info
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    print(f"    - Origin: {origin}")

    buckets = discover_buckets_in_text(html)
    print(f"[*] Discovered {len(buckets)} candidate S3 buckets on page.")

    for b in buckets:
        print(f"    -> {b}")

    results = []
    for b in buckets:
        print()
        res = scan_bucket(b, do_write_test=do_write_test)
        print(f"    => Severity: {res['severity']}\n")
        results.append(res)

    if not buckets:
        print("[*] No S3 buckets detected in page content.")
    return results

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(
        description="CLI tool for detecting vulnerable S3 buckets (from bucket names or website URLs)."
    )
    parser.add_argument(
        "-b", "--bucket",
        help="Single bucket name to scan (e.g. mycompany-assets)"
    )
    parser.add_argument(
        "-l", "--list",
        help="File with one bucket name per line"
    )
    parser.add_argument(
        "-u", "--url",
        help="Website URL to scan for S3 buckets (e.g. https://target.com)"
    )
    parser.add_argument(
        "--test-write",
        action="store_true",
        help="Enable test write (only use in scope with permission!)"
    )

    args = parser.parse_args()

    # Mode 1: URL → discover buckets → scan
    if args.url:
        scan_website(args.url, do_write_test=args.test_write)
        return

    # Mode 2: bucket / list
    buckets = []
    if args.bucket:
        buckets.append(args.bucket)
    if args.list:
        with open(args.list, "r", encoding="utf-8") as f:
            for line in f:
                name = line.strip()
                if name:
                    buckets.append(name)

    if not buckets:
        print("[-] No buckets or URL provided. Use -b, -l, or -u.")
        sys.exit(1)

    for b in buckets:
        res = scan_bucket(b, do_write_test=args.test_write)
        print(f"    => Severity: {res['severity']}\n")

if __name__ == "__main__":
    main()
