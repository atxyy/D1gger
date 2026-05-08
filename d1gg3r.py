#!/usr/bin/env python3
"""
Bug Bounty Recon Script
Combines crt.sh certificate transparency (+ subfinder fallback on gateway errors),
DNS resolution, and HTTP probing.
For use against targets with explicit bug bounty programs only.
"""

import json
import sys
import subprocess
import socket
import argparse
import csv
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import time

# ── Config ─────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 5

# crt.sh JSON can be large; TLS read stalls show up as TimeoutError inside urlopen/read.
CRT_SH_TIMEOUT_S = 90

CRT_GATEWAY_ERRORS = frozenset((502, 503, 504))

# ── Phase 1: crt.sh + optional subfinder ──────────────────────────────────

def fetch_crt_subdomains(domain):
    """
    Query crt.sh. Returns (subdomains, need_subfinder_fallback).
    Fallback is triggered on HTTP 502/503/504 or on read/connect timeouts / stalls.
    """
    print(f"\n[+] Phase 1a: Fetching subdomains from crt.sh for {domain}")
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        with urlopen(url, timeout=CRT_SH_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode())
    except TimeoutError:
        print(f"  [!] crt.sh timed out after {CRT_SH_TIMEOUT_S}s (slow/overloaded) — will try subfinder")
        return set(), True
    except HTTPError as e:
        if e.code in CRT_GATEWAY_ERRORS:
            print(f"  [!] crt.sh HTTP {e.code} Bad Gateway — will try subfinder")
            return set(), True
        print(f"  [!] crt.sh HTTP error {e.code}: {e}")
        return set(), False
    except URLError as e:
        print(f"  [!] crt.sh request failed: {e}")
        print("  [!] Try again in a few minutes if crt.sh is overloaded")
        return set(), False
    except json.JSONDecodeError:
        print("  [!] crt.sh returned invalid JSON — likely overloaded, retry later")
        return set(), False

    subdomains = set()
    for record in data:
        for name in record.get("name_value", "").split("\n"):
            name = name.strip()
            if name and not name.startswith("*") and domain in name:
                subdomains.add(name.lower())

    print(f"  [✓] Found {len(subdomains)} unique subdomains via crt.sh")
    return subdomains, False


def fetch_subfinder_subdomains(domain):
    """Enumerate subdomains with ProjectDiscovery subfinder CLI."""
    print(f"\n[+] Phase 1b: Running subfinder for {domain}")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=900,
        )
    except FileNotFoundError:
        print(
            "  [!] subfinder not found on PATH — install from "
            "https://github.com/projectdiscovery/subfinder"
        )
        return set()
    except subprocess.TimeoutExpired:
        print("  [!] subfinder timed out (>15m)")
        return set()

    if result.returncode != 0:
        err = (result.stderr or "").strip() or "(no stderr)"
        print(f"  [!] subfinder exited {result.returncode}: {err[:500]}")
        return set()

    subdomains = set()
    for line in result.stdout.splitlines():
        host = line.strip().lower().rstrip(".")
        if host and domain in host:
            subdomains.add(host)
    subdomains.add(domain.lower())

    print(f"  [✓] Found {len(subdomains)} hosts via subfinder")
    return subdomains


def harvest_subdomains(domain, use_subfinder_on_crt_gateway=True):
    """crt.sh first; on gateway errors run subfinder and merge."""
    crt_hosts, bad_gateway = fetch_crt_subdomains(domain)
    if bad_gateway and use_subfinder_on_crt_gateway:
        crt_hosts |= fetch_subfinder_subdomains(domain)
    return crt_hosts


# ── Phase 2: DNS Resolution ────────────────────────────────────────────────

def resolve_subdomain(subdomain):
    try:
        results = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        return ips
    except socket.gaierror:
        return []

def get_dns_records(domain):
    """Pull TXT, MX, NS records using dig for third-party service discovery"""
    records = {}
    for rtype in ["TXT", "MX", "NS", "CNAME"]:
        try:
            result = subprocess.run(
                ["dig", "+short", rtype, domain],
                capture_output=True, text=True, timeout=5
            )
            records[rtype] = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            records[rtype] = []
    return records

def resolve_all(subdomains):
    print(f"\n[+] Phase 2: DNS resolution for {len(subdomains)} subdomains")
    resolved = {}
    dead = []

    for i, sub in enumerate(sorted(subdomains), 1):
        ips = resolve_subdomain(sub)
        if ips:
            resolved[sub] = ips
            print(f"  [✓] {sub} → {', '.join(ips)}")
        else:
            dead.append(sub)

        # Light rate limiting
        if i % 20 == 0:
            time.sleep(0.5)

    print(f"\n  [✓] Live: {len(resolved)} | Dead/unresolved: {len(dead)}")
    return resolved, dead

# ── Phase 3: HTTP Probing ──────────────────────────────────────────────────

def http_probe(subdomain):
    """Check HTTP/HTTPS status codes and grab basic headers"""
    results = {}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w",
                 "%{http_code}|%{redirect_url}|%{time_total}",
                 "--max-time", str(DEFAULT_TIMEOUT),
                 "-L", "--max-redirs", "3",
                 "-H", "User-Agent: Mozilla/5.0 (compatible; BugBountyRecon/1.0)",
                 url],
                capture_output=True, text=True, timeout=DEFAULT_TIMEOUT + 2
            )
            parts = result.stdout.strip().split("|")
            if len(parts) == 3:
                status, redirect, ttfb = parts
                results[scheme] = {
                    "status": status,
                    "redirect": redirect,
                    "ttfb": ttfb
                }
        except (subprocess.TimeoutExpired, FileNotFoundError):
            results[scheme] = {"status": "timeout", "redirect": "", "ttfb": ""}
    return results

def probe_all(resolved):
    print(f"\n[+] Phase 3: HTTP probing {len(resolved)} live subdomains")
    probed = {}

    for subdomain, ips in resolved.items():
        http_data = http_probe(subdomain)
        probed[subdomain] = {
            "ips": ips,
            "http": http_data
        }

        https_status = http_data.get("https", {}).get("status", "-")
        http_status  = http_data.get("http",  {}).get("status", "-")
        print(f"  {subdomain}")
        print(f"    IPs: {', '.join(ips)}")
        print(f"    HTTPS: {https_status} | HTTP: {http_status}")

    return probed

# ── Phase 4: Third-Party Service Detection ────────────────────────────────

THIRD_PARTY_SIGNATURES = {
    "frontegg":     "Auth platform (Frontegg) — check tenant config",
    "stripe":       "Payment integration",
    "sendgrid":     "Email via SendGrid",
    "mailgun":      "Email via Mailgun",
    "intercom":     "Intercom customer support",
    "segment":      "Segment analytics",
    "amplitude":    "Amplitude analytics",
    "sentry":       "Sentry error tracking",
    "datadog":      "Datadog monitoring",
    "heroku":       "Heroku hosted — check for subdomain takeover",
    "vercel":       "Vercel hosted",
    "netlify":      "Netlify hosted",
    "railway":      "Railway hosted",
    "render":       "Render hosted",
    "supabase":     "Supabase BaaS",
    "firebase":     "Firebase BaaS",
    "cloudfront":   "AWS CloudFront CDN",
    "amazonaws":    "AWS infrastructure",
    "googlecloud":  "Google Cloud",
}

def detect_third_parties(dns_records, subdomains):
    print("\n[+] Phase 4: Third-party service detection")
    findings = []

    all_text = " ".join(
        str(v) for values in dns_records.values() for v in values
    ).lower() + " " + " ".join(subdomains).lower()

    for keyword, description in THIRD_PARTY_SIGNATURES.items():
        if keyword in all_text:
            findings.append((keyword, description))
            print(f"  [!] {keyword.capitalize()} detected — {description}")

    if not findings:
        print("  [-] No known third-party signatures detected in DNS")

    return findings

# ── Phase 5: Triage & Scoring ─────────────────────────────────────────────

INTERESTING_KEYWORDS = [
    "admin", "api", "staging", "dev", "test", "internal",
    "data", "load", "infra", "backend", "dashboard", "cms",
    "auth", "login", "frontegg", "meet", "upload", "beta"
]

def triage(probed):
    print("\n[+] Phase 5: Triage — ranking by interest level")
    scored = []

    for subdomain, data in probed.items():
        score = 0
        notes = []

        # Keyword scoring
        for kw in INTERESTING_KEYWORDS:
            if kw in subdomain:
                score += 2
                notes.append(f"keyword:{kw}")

        # HTTP status scoring
        https_status = data["http"].get("https", {}).get("status", "")
        http_status  = data["http"].get("http",  {}).get("status", "")

        if https_status == "200":
            score += 3
            notes.append("https:200")
        elif https_status == "403":
            score += 2
            notes.append("https:403 (exists but gated)")
        elif https_status == "401":
            score += 2
            notes.append("https:401 (auth required)")
        elif https_status == "302":
            score += 1
            notes.append("https:302 (redirect)")
        elif https_status in ("000", "timeout"):
            score -= 1

        # Redirect leaks info
        redirect = data["http"].get("https", {}).get("redirect", "")
        if redirect:
            notes.append(f"redirects→{redirect}")

        scored.append({
            "subdomain": subdomain,
            "ips": ", ".join(data["ips"]),
            "https_status": https_status,
            "http_status": http_status,
            "score": score,
            "notes": " | ".join(notes)
        })

    scored.sort(key=lambda x: x["score"], reverse=True)

    print("\n  TOP TARGETS (by interest score):")
    print(f"  {'Subdomain':<40} {'HTTPS':>6} {'Score':>6}  Notes")
    print("  " + "-" * 90)
    for item in scored[:15]:
        print(f"  {item['subdomain']:<40} {item['https_status']:>6} {item['score']:>6}  {item['notes']}")

    return scored

# ── Output ─────────────────────────────────────────────────────────────────

def save_output(domain, subdomains, resolved, dead, probed, third_parties, scored, output_dir="."):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{domain.replace('.', '_')}_{timestamp}"
    out = Path(output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Raw subdomains
    p_all = out / f"{base}_subdomains_all.txt"
    with open(p_all, "w") as f:
        f.write("\n".join(sorted(subdomains)))
    print(f"\n[✓] Saved: {p_all}")

    # Live subdomains
    p_live = out / f"{base}_subdomains_live.txt"
    with open(p_live, "w") as f:
        f.write("\n".join(sorted(resolved.keys())))
    print(f"[✓] Saved: {p_live}")

    # Dead subdomains
    p_dead = out / f"{base}_subdomains_dead.txt"
    with open(p_dead, "w") as f:
        f.write("\n".join(sorted(dead)))
    print(f"[✓] Saved: {p_dead}")

    # Full CSV triage report
    csv_path = out / f"{base}_triage.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["subdomain","ips","https_status","http_status","score","notes"])
        writer.writeheader()
        writer.writerows(scored)
    print(f"[✓] Saved: {csv_path}")

    # Summary JSON
    summary = {
        "run_id": base,
        "target": domain,
        "timestamp": timestamp,
        "output_dir": str(out),
        "subdomains_found": len(subdomains),
        "subdomains_live": len(resolved),
        "subdomains_dead": len(dead),
        "third_parties": [{"service": k, "note": v} for k, v in third_parties],
        "top_targets": scored[:10],
    }
    p_summary = out / f"{base}_summary.json"
    with open(p_summary, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[✓] Saved: {p_summary}")
    return base, out

# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bug bounty recon: crt.sh + DNS + HTTP probing",
        epilog="Only use against targets with explicit bug bounty programs."
    )
    parser.add_argument("domain", help="Target domain (e.g. goperfect.com)")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP probing (DNS only)")
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="When crt.sh returns 502/503/504, exit instead of running subfinder",
    )
    parser.add_argument("--output-dir", default=".", help="Directory to save output files")
    args = parser.parse_args()

    domain = args.domain.lower().strip()

    print("=" * 60)
    print(f"  Bug Bounty Recon — {domain}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  For use with explicit bug bounty targets only.")
    print("=" * 60)

    # Phase 1: crt.sh (+ subfinder on crt gateway errors)
    subdomains = harvest_subdomains(
        domain, use_subfinder_on_crt_gateway=not args.no_subfinder
    )
    if not subdomains:
        print("[!] No subdomains found. Exiting.")
        sys.exit(1)

    # Phase 2: DNS
    resolved, dead = resolve_all(subdomains)
    if not resolved:
        print("[!] No live subdomains found via DNS.")

    # Phase 3: DNS enrichment on root domain
    print(f"\n[+] Fetching DNS records for root domain {domain}")
    root_dns = get_dns_records(domain)
    for rtype, values in root_dns.items():
        if values:
            print(f"  {rtype}: {' | '.join(values[:3])}")

    # Phase 4: Third-party detection
    third_parties = detect_third_parties(root_dns, list(subdomains))

    # Phase 5: HTTP probing
    if not args.no_http and resolved:
        probed = probe_all(resolved)
    else:
        probed = {sub: {"ips": ips, "http": {}} for sub, ips in resolved.items()}

    # Phase 6: Triage
    scored = triage(probed) if probed else []

    # Save everything
    save_output(
        domain, subdomains, resolved, dead, probed, third_parties, scored,
        output_dir=args.output_dir,
    )

    print("\n[✓] Recon complete.")
    print(f"    {len(subdomains)} subdomains found → {len(resolved)} live")
    print(f"    {len(third_parties)} third-party services detected")

if __name__ == "__main__":
    main()