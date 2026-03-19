#!/usr/bin/env python3
"""
cor_extended.py

CORS misconfiguration scanner (authorized testing only).
Features added:
 - Accepts origins from: --origin-list (comma-separated), --origins-file (one-per-line),
   or a built-in popular-domain list via --use-popular.
 - Samples N origins by default to avoid noisy scans; override with --all-origins.
 - Optional two-origin reflection test (--two-origin) that runs exactly two origins and reports REFLECTS/NO REFLECTION.
 - Minimal dependencies: requests, optional rich for prettier output.

Usage examples:
  python cor_extended.py https://target.example --use-popular --sample 5
  python cor_extended.py https://target.example --origins-file origins.txt --rate 1
  python cor_extended.py https://target.example --origin-list "https://google.com,https://youtube.com"
  python cor_extended.py https://target.example --two-origin
"""

from __future__ import annotations
import argparse
import json
import random
import string
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import requests

try:
    from rich import print as rprint
    from rich.table import Table
except Exception:
    rprint = print
    Table = None  # type: ignore

VERSION = "1.1.0"

# -------------------------
# Replace or extend the built-in popular origins (schemes included)
# NOTE: This list contains many real-world domains (some adult). Use responsibly.
# -------------------------
POPULAR_ORIGINS = [
    "https://google.com","https://youtube.com","https://facebook.com","https://baidu.com","https://wikipedia.org",
    "https://reddit.com","https://yahoo.com","https://qq.com","https://taobao.com","https://twitter.com",
    "https://google.co.in","https://amazon.com","https://sohu.com","https://tmall.com","https://instagram.com",
    "https://live.com","https://vk.com","https://jd.com","https://sina.com.cn","https://weibo.com",
    "https://google.co.jp","https://yandex.ru","https://360.cn","https://google.co.uk","https://login.tmall.com",
    "https://google.ru","https://google.com.br","https://pornhub.com","https://twitch.tv","https://netflix.com",
    "https://google.com.hk","https://linkedin.com","https://google.de","https://google.fr","https://csdn.net",
    "https://microsoft.com","https://t.co","https://bing.com","https://yahoo.co.jp","https://office.com",
    "https://ebay.com","https://google.it","https://alipay.com","https://google.ca","https://mail.ru",
    "https://msn.com","https://xvideos.com","https://ok.ru","https://microsoftonline.com","https://google.es",
    "https://imgur.com","https://aliexpress.com","https://pages.tmall.com","https://whatsapp.com","https://google.com.mx",
    "https://imdb.com","https://tumblr.com","https://stackoverflow.com","https://wordpress.com","https://wikia.com",
    "https://github.com","https://google.com.tw","https://xhamster.com","https://deloton.com","https://hao123.com",
    "https://amazon.co.jp","https://livejasmin.com","https://google.com.tr","https://blogspot.com","https://paypal.com",
    "https://popads.net","https://google.com.au","https://apple.com","https://bongacams.com","https://googleusercontent.com",
    "https://tribunnews.com","https://pinterest.com","https://xnxx.com","https://coccoc.com","https://savefrom.net",
    "https://youth.cn","https://google.pl","https://diply.com","https://fbcdn.net","https://providr.com",
    "https://adobe.com","https://txxx.com","https://amazon.de","https://dropbox.com","https://detail.tmall.com",
    "https://thestartmagazine.com","https://google.co.id","https://pixnet.net","https://tianya.cn","https://quora.com",
    "https://bbc.co.uk","https://cnn.com","https://amazon.co.uk","https://bbc.com","https://amazonaws.com"
]

# -------------------------
# Helper dataclasses
# -------------------------
@dataclass
class Finding:
    id: str
    title: str
    severity: str  # low/medium/high/info
    evidence: Dict[str, str]
    recommendation: str

@dataclass
class ScanResult:
    target: str
    tested_origin: str
    status_code: Optional[int]
    response_headers: Dict[str, str]
    preflight_status_code: Optional[int]
    preflight_headers: Dict[str, str]
    findings: List[Finding]
    scanned_at: str

# -------------------------
# Utility functions
# -------------------------
def gen_random_origin() -> str:
    s = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"https://scanner-{s}.example"

def normalize_headers(h: Dict[str, str]) -> Dict[str, str]:
    # Lowercase keys for easy lookup
    return {k.lower(): v for k, v in h.items()}

# -------------------------
# Analysis heuristics (same as before, with small adjustments)
# -------------------------
def analyze_cors(
    target: str,
    origin: str,
    resp_headers: Dict[str, str],
    pre_headers: Optional[Dict[str, str]],
    status_code: Optional[int],
    pre_status_code: Optional[int],
) -> List[Finding]:
    findings: List[Finding] = []
    rh = normalize_headers(resp_headers)
    ph = normalize_headers(pre_headers or {})

    ac_ao = rh.get("access-control-allow-origin")
    ac_ac = rh.get("access-control-allow-credentials")
    ac_am = rh.get("access-control-allow-methods")
    ac_ah = rh.get("access-control-allow-headers")
    ac_ex = rh.get("access-control-expose-headers")
    ac_ma = rh.get("access-control-max-age")

    # 1: wildcard + credentials (danger)
    if ac_ao and ac_ao.strip() == "*" and ac_ac and ac_ac.strip().lower() == "true":
        findings.append(Finding(
            id="CORS-001",
            title="Wildcard origin with credentials allowed",
            severity="high",
            evidence={
                "access-control-allow-origin": ac_ao,
                "access-control-allow-credentials": ac_ac,
            },
            recommendation="Avoid returning '*' when Access-Control-Allow-Credentials is true. Return explicit allowed origins from a server-side allowlist.",
        ))

    # 2: reflected origin (server echoes origin back)
    if ac_ao and ac_ao.strip() == origin:
        findings.append(Finding(
            id="CORS-002",
            title="Reflected Origin (unvalidated echo)",
            severity="high",
            evidence={
                "request_origin": origin,
                "access-control-allow-origin": ac_ao,
            },
            recommendation="Don't echo incoming Origin header. Validate the origin against an allowlist and return only exact matches from that list.",
        ))

    # 3: credentials allowed with possibly-permissive origin
    if ac_ac and ac_ac.strip().lower() == "true" and ac_ao:
        if ac_ao.strip() == "*" or ac_ao.strip().endswith(".example"):
            findings.append(Finding(
                id="CORS-003",
                title="Credentials allowed with possibly-permissive origin",
                severity="medium",
                evidence={"access-control-allow-origin": ac_ao, "access-control-allow-credentials": ac_ac},
                recommendation="Only set Access-Control-Allow-Credentials: true when returning an explicit, validated origin (not '*').",
            ))

    # 4: preflight echoes weird stuff
    if pre_headers:
        pre_ao = ph.get("access-control-allow-origin")
        pre_ac = ph.get("access-control-allow-credentials")
        pre_am = ph.get("access-control-allow-methods")
        if pre_ao and pre_ao.strip() == origin:
            findings.append(Finding(
                id="CORS-004",
                title="Preflight reflected origin",
                severity="high",
                evidence={"preflight_access_control_allow_origin": pre_ao},
                recommendation="Validate preflight origin and avoid reflecting arbitrary origins in responses to OPTIONS requests.",
            ))
        if pre_am and any(m in pre_am.upper() for m in ("PUT", "DELETE", "PATCH")):
            findings.append(Finding(
                id="CORS-005",
                title="Preflight allows risky methods",
                severity="medium",
                evidence={"access-control-allow-methods": pre_am},
                recommendation="Restrict allowed methods to the minimum necessary for intended functionality.",
            ))

    # 5: expose headers that might be sensitive
    if ac_ex:
        if any(x in ac_ex.lower() for x in ("set-cookie", "authorization", "cookie")):
            findings.append(Finding(
                id="CORS-006",
                title="Exposes potentially sensitive headers",
                severity="medium",
                evidence={"access-control-expose-headers": ac_ex},
                recommendation="Do not expose sensitive headers unless absolutely required.",
            ))

    # 6: very long max-age (exposure window)
    if ac_ma:
        try:
            val = int(ac_ma.strip())
            if val > 86400 * 30:  # > 30 days
                findings.append(Finding(
                    id="CORS-007",
                    title="Large Access-Control-Max-Age",
                    severity="low",
                    evidence={"access-control-max-age": ac_ma},
                    recommendation="Use conservative max-age values (minutes to hours) to limit exposure window.",
                ))
        except Exception:
            pass

    # 7: no CORS headers at all -> info
    if not any([ac_ao, ac_ac, ac_am, ac_ah, ac_ex, ac_ma]):
        findings.append(Finding(
            id="CORS-000",
            title="No CORS headers observed",
            severity="info",
            evidence={},
            recommendation="No CORS headers were set in the tested response",
        ))

    return findings

# -------------------------
# Scanner actions
# -------------------------
def perform_requests(
    url: str,
    origin: str,
    do_preflight: bool = True,
    timeout: float = 10.0,
    test_method_for_preflight: str = "PUT",
) -> ScanResult:
    s = requests.Session()
    headers = {"Origin": origin, "User-Agent": f"cors-scanner/{VERSION}"}
    status_code = None
    resp_headers = {}
    try:
        r = s.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        status_code = r.status_code
        resp_headers = r.headers
    except requests.RequestException:
        resp_headers = {}
        status_code = None

    preflight_status = None
    preflight_headers = {}
    if do_preflight:
        opt_headers = {
            "Origin": origin,
            "Access-Control-Request-Method": test_method_for_preflight,
            "Access-Control-Request-Headers": "X-Test-Header",
            "User-Agent": f"cors-scanner/{VERSION}",
        }
        try:
            r2 = s.options(url, headers=opt_headers, timeout=timeout, allow_redirects=False)
            preflight_status = r2.status_code
            preflight_headers = r2.headers
        except requests.RequestException:
            preflight_status = None
            preflight_headers = {}

    scanned_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    findings = analyze_cors(url, origin, dict(resp_headers), dict(preflight_headers), status_code, preflight_status)
    return ScanResult(
        target=url,
        tested_origin=origin,
        status_code=status_code,
        response_headers=dict(resp_headers),
        preflight_status_code=preflight_status,
        preflight_headers=dict(preflight_headers),
        findings=findings,
        scanned_at=scanned_at,
    )

# -------------------------
# Output helpers
# -------------------------
def print_text_result(r: ScanResult) -> None:
    if Table and rprint is not print:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Target")
        table.add_column("Origin")
        table.add_column("Status")
        table.add_column("Findings")
        table.add_row(r.target, r.tested_origin, str(r.status_code or "N/A"), str(len(r.findings)))
        rprint(table)
        for f in r.findings:
            rprint(f"[bold]{f.id}[/bold] [yellow]{f.title}[/yellow] (severity={f.severity})")
            for k, v in f.evidence.items():
                rprint(f"  • {k}: {v}")
            rprint(f"  Recommendation: {f.recommendation}\n")
    else:
        print(f"Target: {r.target}")
        print(f"Tested Origin: {r.tested_origin}")
        print(f"Status: {r.status_code or 'N/A'}")
        print(f"Findings: {len(r.findings)}")
        for f in r.findings:
            print(f"- {f.id} | {f.title} | severity={f.severity}")
            for k, v in f.evidence.items():
                print(f"    {k}: {v}")
            print(f"    Recommendation: {f.recommendation}")
        print("----")

# -------------------------
# CLI and main loop
# -------------------------
def load_origins(args) -> List[str]:
    # Collect origins from --origin-list, --origins-file, or built-in
    origins: List[str] = []
    if args.origin_list:
        origins = [o.strip() for o in args.origin_list.split(",") if o.strip()]
    elif args.origins_file:
        try:
            with open(args.origins_file, "r") as fh:
                origins = [ln.strip() for ln in (l for l in fh) if ln.strip()]
        except Exception as e:
            print(f"Failed to read origins file: {e}", file=sys.stderr)
            origins = []
    elif args.use_popular:
        origins = POPULAR_ORIGINS.copy()

    # Normalize: ensure scheme present (if user supplied plain domain)
    normalized = []
    for o in origins:
        if o.startswith("http://") or o.startswith("https://"):
            normalized.append(o)
        else:
            normalized.append("https://" + o)  # prefer https by default

    return normalized

def main(argv=None):
    p = argparse.ArgumentParser(description="CORS misconfiguration scanner (authorized testing only)")
    p.add_argument("target", nargs="?", help="Target URL to scan (or provide -f/--file for multiple)")
    p.add_argument("-f", "--file", help="File with newline-separated targets (URL per line)")
    p.add_argument("--origin", help="Single origin to simulate (overrides random origin unless --origin-list/--use-popular set)")
    p.add_argument("--origin-list", help="Comma-separated origins to test (overrides random origin). e.g. 'https://google.com,https://youtube.com'")
    p.add_argument("--origins-file", help="File with newline-separated origins to test (one per line)")
    p.add_argument("--use-popular", action="store_true", help="Use built-in popular-domain origins list (sampleed by default)")
    p.add_argument("--sample", type=int, default=5, help="If multiple origins provided, sample at most N origins (default 5). Use --all-origins to disable.")
    p.add_argument("--all-origins", action="store_true", help="When set, test all provided origins (use with care).")
    p.add_argument("--two-origin", action="store_true", help="Run a two-origin reflection test (picks two origins and reports REFLECTS/NO REFLECTION).")
    p.add_argument("--no-preflight", dest="preflight", action="store_false", help="Do not perform OPTIONS preflight tests")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds")
    p.add_argument("--method", default="PUT", help="Method to use in Access-Control-Request-Method for preflight")
    p.add_argument("--rate", type=float, default=0.5, help="Rate limit (requests per second) for batch scans")
    p.add_argument("--output", choices=("text", "json"), default="text", help="Output format")
    p.add_argument("--version", action="store_true")
    args = p.parse_args(argv)

    if args.version:
        print(f"cor-extended {VERSION}")
        return 0

    targets: List[str] = []
    if args.file:
        try:
            with open(args.file, "r") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        targets.append(ln)
        except Exception as e:
            print(f"Failed to read file: {e}", file=sys.stderr)
            return 2
    elif args.target:
        targets.append(args.target)
    else:
        p.print_help()
        return 1

    # Prepare origins
    origins = load_origins(args)
    if args.origin:
        # single origin provided on CLI; ensure it's included if no other list supplied
        if not origins:
            if args.origin.startswith("http://") or args.origin.startswith("https://"):
                origins = [args.origin]
            else:
                origins = ["https://" + args.origin]
    if not origins:
        # default behaviour: single random origin (like previous script)
        origins = [gen_random_origin()]

    # Sample origins unless user requested all
    if not args.all_origins and len(origins) > args.sample:
        origins = random.sample(origins, args.sample)

    # If two-origin mode, ensure exactly two origins (pick or reduce)
    if args.two_origin:
        if len(origins) >= 2:
            origins = origins[:2]
        else:
            # If only one origin available, add a random/generated one to compare
            origins = origins + [gen_random_origin()]

    results: List[ScanResult] = []
    # run scans (target x origins)
    for tidx, tgt in enumerate(targets):
        for oidx, origin in enumerate(origins):
            # rate limiting
            if args.rate and (tidx > 0 or oidx > 0):
                time.sleep(max(0, 1.0 / args.rate))

            r = perform_requests(tgt, origin, do_preflight=args.preflight, timeout=args.timeout, test_method_for_preflight=args.method)
            results.append(r)
            if args.output == "text":
                print_text_result(r)

    # If two-origin mode, do a simple reflection check and print concise result
    if args.two_origin and len(origins) >= 2:
        # find the two results per target and check if the server echoed each origin
        summary = []
        for tgt in targets:
            res_for_tgt = [r for r in results if r.target == tgt]
            # group by origin order
            if len(res_for_tgt) < 2:
                continue
            r1, r2 = res_for_tgt[0], res_for_tgt[1]
            ao1 = normalize_headers(r1.response_headers).get("access-control-allow-origin")
            ao2 = normalize_headers(r2.response_headers).get("access-control-allow-origin")
            reflects = (ao1 and ao1.strip() == r1.tested_origin) and (ao2 and ao2.strip() == r2.tested_origin)
            # also check wildcard case
            wildcard = (ao1 and ao1.strip() == "*") or (ao2 and ao2.strip() == "*")
            summary.append({"target": tgt, "reflects_both": reflects, "wildcard_seen": wildcard,
                            "a1": ao1 or "<none>", "a2": ao2 or "<none>", "origin1": r1.tested_origin, "origin2": r2.tested_origin})
        # print summary in readable form
        for s in summary:
            if s["reflects_both"]:
                rprint(f"[bold red]REFLECTS[/bold red] {s['target']} echoes both origins (evidence: {s['a1']} / {s['a2']})")
            elif s["wildcard_seen"]:
                rprint(f"[bold yellow]WILDCARD[/bold yellow] {s['target']} returned '*' for at least one origin.")
            else:
                rprint(f"[bold green]NO REFLECTION[/bold green] {s['target']} did not echo both origins. ({s['a1']} / {s['a2']})")

    # JSON output option
    if args.output == "json":
        out = []
        for r in results:
            ro = asdict(r)
            ro["findings"] = [asdict(f) for f in r.findings]
            out.append(ro)
        print(json.dumps(out, indent=2))

    return 0

if __name__ == "__main__":
    # small typo-safe alias used in args earlier
    # support both --two-origin and --two_origin flags backwards-compat
    # parse sys.argv for either flag naming
    if "--two_origin" in sys.argv:
        sys.argv[sys.argv.index("--two_origin")] = "--two-origin"
    exit(main())
