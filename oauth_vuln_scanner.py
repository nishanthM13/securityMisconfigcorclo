#!/usr/bin/env python3
"""
oauth_vuln_scanner.py
Passive OAuth/OIDC vulnerability finder (CLI).

- Passive only: GET requests, header checks, JS static analysis.
- Detects a set of common OAuth/OIDC misconfigurations and surfaces them with risk levels.

Author: ChatGPT (adapted for Kali)
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import certifi
import json
import re
import sys
import time
import urllib3
from urllib.parse import urljoin, urlparse

import requests

# ------------------
USER_AGENT = "OAuthVulnScanner/1.0 (+kali)"
COMMON_OPENID = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth2-authorization-server"
]
COMMON_AUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/oauth/token", "/oauth2/token", "/token",
    "/.well-known/jwks.json", "/.well-known/jwks_uri", "/jwks"
]
COMMON_SUBDOMAIN_PREFIXES = [
    "auth", "accounts", "login", "sso", "identity", "id", "oauth", "oauth2", "signin", "users"
]
JS_SRC_REGEX = re.compile(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', flags=re.IGNORECASE)
OAUTH_KEYWORDS = [
    "response_type", "response_type=", "openid", "oauth",
    ".well-known/openid-configuration", "authorization_endpoint",
    "token_endpoint", "jwks_uri"
]
# regexes to find URLs in JS that look like oauth endpoints or discovery
OAUTH_URL_PATTERNS = [
    r'https?://[A-Za-z0-9\.\-:_]+/[^"\']*\.well-known/(?:openid-configuration|oauth-authorization-server|oauth2-authorization-server)',
    r'https?://[A-Za-z0-9\.\-:_]+/[^"\']*(?:/oauth2?/authorize|/authorize)[^"\']*',
    r'https?://[A-Za-z0-9\.\-:_]+/[^"\']*(?:/oauth2?/token|/token)[^"\']*',
    r'https?://[A-Za-z0-9\.\-:_]+/[^"\']*/\.well-known/jwks(?:\.json)?',
]
URL_RX = re.compile("|".join(OAUTH_URL_PATTERNS), re.IGNORECASE)

# secret patterns
CLIENT_SECRET_RX = re.compile(r'client_secret["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_\.=]{8,})["\']', re.IGNORECASE)
CLIENT_ID_RX = re.compile(r'client_id["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_\.=]+)["\']', re.IGNORECASE)
REDIRECT_URI_RX = re.compile(r'redirect_uri["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE)
TOKEN_LITERAL_RX = re.compile(r'(access_token|id_token|id_token_hint|refresh_token)', re.IGNORECASE)

# ------------------
def build_session(verify_cert=True):
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.verify = certifi.where() if verify_cert else False
    if not verify_cert:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    adapter = requests.adapters.HTTPAdapter(pool_maxsize=40, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def safe_get(session, url, timeout=6):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        return {"url": r.url, "status": r.status_code, "text": r.text, "headers": r.headers, "error": None}
    except requests.exceptions.SSLError as e:
        return {"url": url, "status": None, "text": None, "headers": {}, "error": f"SSL error: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"url": url, "status": None, "text": None, "headers": {}, "error": f"Connection error: {e}"}
    except requests.exceptions.Timeout:
        return {"url": url, "status": None, "text": None, "headers": {}, "error": "Timeout"}
    except Exception as e:
        return {"url": url, "status": None, "text": None, "headers": {}, "error": f"Other error: {e}"}

# ------------------
def probe_well_known(session, base, timeout=6):
    findings = []
    for p in COMMON_OPENID:
        u = urljoin(base, p)
        r = safe_get(session, u, timeout=timeout)
        item = {"url": u, "status": r["status"], "error": r["error"], "json": None}
        if r["status"] == 200 and r["text"]:
            try:
                item["json"] = json.loads(r["text"])
            except Exception:
                item["json"] = None
        findings.append(item)
    return findings

def probe_common_paths(session, base, timeout=6):
    found = []
    for p in COMMON_AUTH_PATHS:
        u = urljoin(base, p)
        r = safe_get(session, u, timeout=timeout)
        if r["status"] and r["status"] < 400:
            found.append({"url": u, "status": r["status"]})
    return found

def generate_subdomains(domain):
    candidates = []
    for prefix in COMMON_SUBDOMAIN_PREFIXES:
        candidates.append(f"https://{prefix}.{domain}/")
        candidates.append(f"http://{prefix}.{domain}/")
    return candidates

def probe_subdomains_concurrent(session, target_url, timeout=6, max_workers=10, verbose=False):
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return []
    parts = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    candidates = generate_subdomains(domain)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(safe_get, session, c, timeout): c for c in candidates}
        for fut in as_completed(futs):
            c = futs[fut]
            r = fut.result()
            results.append({"candidate": c, "status": r["status"], "error": r["error"], "headers": r.get("headers", {}), "final_url": r["url"]})
            if verbose:
                print(f"  -> {c} status={r['status']} error={r['error']}")
    return results

def extract_js_links_from_html(base, html_text):
    js_urls = set()
    try:
        for m in JS_SRC_REGEX.finditer(html_text):
            src = m.group(1).strip()
            full = urljoin(base, src)
            js_urls.add(full)
    except Exception:
        pass
    return sorted(js_urls)

def scan_js_for_oauth_concurrent(session, js_urls, timeout=6, max_workers=10, verbose=False):
    results = []
    if not js_urls:
        return results
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(safe_get, session, js, timeout): js for js in js_urls}
        for fut in as_completed(futs):
            js = futs[fut]
            r = fut.result()
            matches = []
            urls = []
            secrets = []
            redirect_uris = []
            tokens = []
            if r["text"]:
                low = r["text"].lower()
                for kw in OAUTH_KEYWORDS:
                    if kw in low:
                        matches.append(kw)
                for um in URL_RX.findall(r["text"]):
                    if um:
                        urls.append(um if isinstance(um, str) else next(filter(None, um)))
                for m in CLIENT_SECRET_RX.finditer(r["text"]):
                    secrets.append(m.group(1))
                for m in CLIENT_ID_RX.finditer(r["text"]):
                    secrets.append("client_id:"+m.group(1))
                for m in REDIRECT_URI_RX.finditer(r["text"]):
                    redirect_uris.append(m.group(1))
                for m in TOKEN_LITERAL_RX.finditer(r["text"]):
                    tokens.append(m.group(1))
            entry = {"js_url": js, "status": r["status"], "error": r["error"],
                     "matches": sorted(set(matches)), "discovered_urls": sorted(set(urls)),
                     "secrets": sorted(set(secrets)), "redirect_uris": sorted(set(redirect_uris)),
                     "token_literals": sorted(set(tokens))}
            results.append(entry)
            if verbose:
                print(f"  -> scanned JS {js} status={r['status']} matches={entry['matches']} secrets={len(entry['secrets'])}")
    return results

# ------------------
def analyze_oidc_config(config_json):
    notes = []
    if not config_json:
        notes.append(("MISSING_JSON", "No JSON metadata parsed from discovery endpoint.", "LOW"))
        return notes

    # response types
    rt = config_json.get("response_types_supported") or config_json.get("response_type_supported") or []
    try:
        rts = [v.lower() for v in rt]
    except Exception:
        rts = []
    if any(("token" in v or "id_token" in v) for v in rts):
        notes.append(("IMPLICIT_FLOW", "Implicit/token-based response types advertised (implicit flow).", "HIGH"))

    tmethods = config_json.get("token_endpoint_auth_methods_supported") or []
    if isinstance(tmethods, list) and "none" in [m.lower() for m in tmethods]:
        notes.append(("TOKEN_AUTH_NONE", "token_endpoint_auth_methods_supported includes 'none' (public client behavior).", "HIGH"))

    if not config_json.get("jwks_uri"):
        notes.append(("MISSING_JWKS", "jwks_uri missing from metadata.", "HIGH"))

    if not config_json.get("issuer") or not config_json.get("authorization_endpoint"):
        notes.append(("MISSING_ISSUER_OR_AUTHZ", "issuer or authorization_endpoint field missing from metadata.", "HIGH"))

    if not config_json.get("code_challenge_methods_supported"):
        notes.append(("MISSING_PKCE", "code_challenge_methods_supported missing (PKCE might not be supported).", "MEDIUM"))

    if not config_json.get("introspection_endpoint"):
        notes.append(("MISSING_INTROSPECTION", "introspection_endpoint not present (may be normal).", "LOW"))

    if not config_json.get("revocation_endpoint"):
        notes.append(("MISSING_REVOCATION", "revocation_endpoint not present (may be normal).", "LOW"))

    # check for insecure http in endpoints
    for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        v = config_json.get(k)
        if v and v.strip().lower().startswith("http://"):
            notes.append(("HTTP_ENDPOINT", f"{k} uses http:// (insecure transport).", "HIGH"))

    return notes

# ------------------
def check_cors(headers):
    aco = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
    if not aco:
        return None
    if aco.strip() == "*" :
        return ("CORS_WILDCARD", "Access-Control-Allow-Origin: *", "HIGH")
    # specific hosts allowed is less severe
    return ("CORS_SPECIFIC", f"Access-Control-Allow-Origin: {aco}", "LOW")

def check_security_headers(headers):
    issues = []
    if "strict-transport-security" not in {k.lower() for k in headers.keys()}:
        issues.append(("MISSING_HSTS", "Strict-Transport-Security header missing.", "MEDIUM"))
    if "x-frame-options" not in {k.lower() for k in headers.keys()}:
        issues.append(("MISSING_XFO", "X-Frame-Options header missing.", "MEDIUM"))
    if "content-security-policy" not in {k.lower() for k in headers.keys()}:
        issues.append(("MISSING_CSP", "Content-Security-Policy header missing.", "MEDIUM"))
    return issues

# ------------------
def scan_target(target, verify=True, timeout=6, fast=False, verbose=False, concurrency=12):
    session = build_session(verify_cert=verify)
    result = {"target": target, "timestamp": int(time.time()),
              "well_known": [], "common_paths": [], "subdomain_probes": [],
              "homepage": {}, "js_findings": [], "discovered_url_probes": [], "vulnerabilities": []}

    # normalize
    parsed = urlparse(target)
    if not parsed.scheme:
        target = "https://" + target
        parsed = urlparse(target)
    if not target.endswith("/"):
        target = target + "/"

    if verbose:
        print(f"[+] scanning {target} (timeout={timeout}, verify={verify})")

    # 1) well-known
    wk = probe_well_known(session, target, timeout=timeout)
    result["well_known"] = wk
    for w in wk:
        if w.get("json"):
            notes = analyze_oidc_config(w["json"])
            for code, text, sev in notes:
                result["vulnerabilities"].append({"code": code, "desc": text, "severity": sev, "source": w["url"]})

    # 2) common paths
    result["common_paths"] = probe_common_paths(session, target, timeout=timeout)

    # 3) subdomains
    sub_results = probe_subdomains_concurrent(session, target, timeout=timeout, max_workers=min(concurrency, 20), verbose=verbose)
    result["subdomain_probes"] = sub_results
    # check security headers and CORS on discovered auth subdomains with positive response
    for s in sub_results:
        if s.get("status"):
            hdrs = {k.lower(): v for k, v in (s.get("headers") or {}).items()}
            c = check_cors(hdrs)
            if c:
                result["vulnerabilities"].append({"code": c[0], "desc": c[1], "severity": c[2], "source": s["candidate"]})
            sh = check_security_headers(hdrs)
            for it in sh:
                result["vulnerabilities"].append({"code": it[0], "desc": it[1], "severity": it[2], "source": s["candidate"]})

    # 4) homepage + linked JS
    home = safe_get(session, target, timeout=timeout)
    if home["text"]:
        result["homepage"]["status"] = home["status"]
        found_keywords = [k for k in OAUTH_KEYWORDS if k in home["text"].lower()]
        result["homepage"]["keywords"] = sorted(set(found_keywords))
        js_links = extract_js_links_from_html(target, home["text"])
        result["homepage"]["linked_js"] = js_links

        # concurrent JS scan
        js_findings = scan_js_for_oauth_concurrent(session, js_links, timeout=timeout, max_workers=min(concurrency, 30), verbose=verbose)
        result["js_findings"] = js_findings

        # aggregate discovered urls from JS and probe them
        all_urls = []
        for j in js_findings:
            all_urls.extend(j.get("discovered_urls", []))
            # detect hardcoded client secrets/ids/redirects/tokens
            if j.get("secrets"):
                for s in j["secrets"]:
                    result["vulnerabilities"].append({"code": "HARDCODE_SECRET", "desc": f"Hardcoded secret or client_id in JS: {s}", "severity": "HIGH", "source": j["js_url"]})
            if j.get("redirect_uris"):
                for ruri in j["redirect_uris"]:
                    result["vulnerabilities"].append({"code": "HARDCODE_REDIRECT", "desc": f"Hardcoded redirect_uri in JS: {ruri}", "severity": "MEDIUM", "source": j["js_url"]})
            if j.get("token_literals"):
                for t in j["token_literals"]:
                    result["vulnerabilities"].append({"code": "TOKEN_LITERAL_IN_JS", "desc": f"Token-related literal in JS: {t}", "severity": "HIGH", "source": j["js_url"]})
            # third-party IdP references (informational)
            for u in j.get("discovered_urls", []):
                parsedu = urlparse(u)
                if parsedu and parsedu.hostname and not parsedu.hostname.endswith(parsed.hostname):
                    result["vulnerabilities"].append({"code": "THIRD_PARTY_IDP", "desc": f"External IdP referenced in JS: {parsedu.hostname}", "severity": "LOW", "source": j["js_url"]})
        # probe discovered URLs
        probed = []
        if all_urls:
            unique = sorted(set(all_urls))
            if verbose: print(f"[+] probing {len(unique)} URLs discovered in JS")
            with ThreadPoolExecutor(max_workers=min(len(unique), 20)) as ex:
                futs = {ex.submit(safe_get, session, u, timeout): u for u in unique}
                for fut in as_completed(futs):
                    u = futs[fut]
                    r = fut.result()
                    item = {"url": u, "status": r["status"], "error": r["error"], "json": None, "headers": r.get("headers", {})}
                    if r["status"] == 200 and r["text"] and "/.well-known/" in u:
                        try:
                            item["json"] = json.loads(r["text"])
                        except Exception:
                            item["json"] = None
                    probed.append(item)
                    # analyze any returned discovery json
                    if item.get("json"):
                        notes = analyze_oidc_config(item["json"])
                        for code, text, sev in notes:
                            result["vulnerabilities"].append({"code": code, "desc": text, "severity": sev, "source": u})
                    # check CORS on discovered URL
                    hdrs = {k.lower(): v for k, v in (item.get("headers") or {}).items()}
                    c = check_cors(hdrs)
                    if c:
                        result["vulnerabilities"].append({"code": c[0], "desc": c[1], "severity": c[2], "source": u})
            result["discovered_url_probes"] = probed

    else:
        result["homepage"]["error"] = home["error"]

    # deduplicate vulnerabilities by (code,desc,source)
    uniq = {}
    for v in result["vulnerabilities"]:
        key = (v.get("code"), v.get("desc"), v.get("source"))
        if key not in uniq:
            uniq[key] = v
    result["vulnerabilities"] = list(uniq.values())

    # categorize summary counts
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in result["vulnerabilities"]:
        sev = v.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    result["_summary"] = {"high": counts["HIGH"], "medium": counts["MEDIUM"], "low": counts["LOW"], "total": len(result["vulnerabilities"])}
    return result

# ------------------
def print_report(res):
    print("\n=== OAuth Vulnerability Scan Report ===")
    print("Target:", res["target"])
    print("Timestamp:", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(res["timestamp"])))
    print("\nSummary: HIGH:", res["_summary"]["high"], "MEDIUM:", res["_summary"]["medium"], "LOW:", res["_summary"]["low"], "TOTAL:", res["_summary"]["total"])

    if res.get("well_known"):
        print("\n[.well-known discovery probes]")
        for w in res["well_known"]:
            print(" -", w["url"], "status:", w["status"], "error:", w["error"])
            if w.get("json"):
                jm = w["json"]
                for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
                    if k in jm:
                        print("    ", k + ":", jm.get(k))

    if res.get("subdomain_probes"):
        print("\n[Auth subdomain probes]")
        for s in res["subdomain_probes"]:
            print(" -", s["candidate"], "status:", s["status"], "error:", s["error"])

    if res.get("homepage"):
        print("\n[Homepage findings]")
        if res["homepage"].get("keywords"):
            print(" - OAuth keywords on homepage:", ", ".join(res["homepage"]["keywords"]))
        else:
            if res["homepage"].get("error"):
                print(" - Homepage error:", res["homepage"]["error"])
            else:
                print(" - No OAuth keywords on homepage.")

    if res.get("js_findings"):
        print("\n[Linked JS files scanned]")
        for j in res["js_findings"]:
            brief = f"{j['js_url']} status:{j['status']} matches:{','.join(j['matches']) or 'none'} secrets:{len(j['secrets'])} urls:{len(j['discovered_urls'])}"
            print(" -", brief)

    if res.get("discovered_url_probes"):
        print("\n[Discovered URLs probed]")
        for d in res["discovered_url_probes"]:
            print(" -", d["url"], "status:", d["status"], "error:", d["error"])

    if res.get("vulnerabilities"):
        print("\n[Detected issues (sample)]")
        # sort by severity
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        vulns = sorted(res["vulnerabilities"], key=lambda x: (order.get(x.get("severity","LOW"), 2), x.get("code")))
        for v in vulns:
            print(f" [{v['severity']}] {v['code']} - {v['desc']} (source: {v.get('source')})")

# ------------------
def main():
    ap = argparse.ArgumentParser(description="Passive OAuth/OIDC vulnerability finder.")
    ap.add_argument("target", help="Target base URL or host (e.g., https://example.com or example.com)")
    ap.add_argument("-o", "--output", help="Write JSON results to file", default=None)
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    ap.add_argument("--timeout", type=int, default=6, help="HTTP timeout (seconds)")
    ap.add_argument("--fast", action="store_true", help="Faster mode (shorter timeouts, higher concurrency)")
    ap.add_argument("--concurrency", type=int, default=12, help="Concurrency for subdomain/JS probes")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = ap.parse_args()

    verify = not args.insecure
    timeout = args.timeout
    concurrency = args.concurrency
    if args.fast:
        timeout = max(2, int(timeout/2))
        concurrency = max(concurrency, 24)

    try:
        res = scan_target(args.target, verify=verify, timeout=timeout, fast=args.fast, verbose=args.verbose, concurrency=concurrency)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as e:
        print("[!] Error:", e)
        sys.exit(1)

    print_report(res)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(res, fh, indent=2)
            print("\n[+] Results saved to", args.output)
        except Exception as e:
            print("[!] Failed to write output file:", e)

if __name__ == "__main__":
    main()
