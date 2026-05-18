#!/usr/bin/env python3
"""
Bug Bounty Recon Script
Combines crt.sh certificate transparency (+ subfinder fallback on gateway errors),
DNS resolution, and HTTP probing.
For use against targets with explicit bug bounty programs only.
"""

import argparse
import csv
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

__version__ = "1.2.0"

# DNS hostname limits (RFC 1035 / IDNA)
_MAX_HOSTNAME_LEN = 253
_MAX_LABEL_LEN = 63

# ── Config ─────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 5
DEFAULT_WORKERS = 32

# crt.sh: quick probe first, then full wildcard fetch only if the service responds.
CRT_SH_PROBE_TIMEOUT_S = 6   # small exact-match query — fail fast when crt.sh is down
CRT_SH_FETCH_TIMEOUT_S = 45  # full %.domain JSON (large domains may still need this long)
CRT_SH_PROBE_READ_BYTES = 2048

CRT_GATEWAY_ERRORS = frozenset((502, 503, 504))

# Parent dirs where save_output / server.py write scan runs
_ARTIFACT_DIR_NAMES = ("runs", "recon-out", "out", "output")

# Scan pipeline (shown at start + on each phase banner)
SCAN_PHASES: tuple[tuple[int, str, str], ...] = (
    (1, "Subdomain discovery", "crt.sh + subfinder in parallel (merged)"),
    (2, "DNS resolution", "resolve each hostname to IPv4"),
    (3, "Apex DNS records", "TXT, MX, NS, CNAME on the root domain"),
    (4, "Third-party detection", "fingerprint SaaS/CDN from DNS + hostnames"),
    (5, "HTTP probing", "HTTPS/HTTP status, redirects, timing"),
    (6, "Triage & scoring", "rank targets by interest"),
    (7, "Save artifacts", "write run folder (txt, csv, json)"),
)
TOTAL_PHASES = len(SCAN_PHASES)


def print_phase_roadmap(*, skip_http: bool = False) -> None:
    print("\n  Scan pipeline:")
    for num, title, detail in SCAN_PHASES:
        skip = skip_http and num == 5
        flag = "  [skipped with --no-http]" if skip else ""
        print(f"    {num}/{TOTAL_PHASES}  {title}{flag}")
        print(f"         {detail}")


def phase_start(num: int, title: str, detail: str = "") -> None:
    print(f"\n{'─' * 60}")
    print(f"  Phase {num}/{TOTAL_PHASES} — {title}")
    if detail:
        print(f"  ⋯ {detail}")
    sys.stdout.flush()


def phase_done(msg: str) -> None:
    print(f"  [✓] {msg}")
    sys.stdout.flush()


def _progress(label: str, done: int, total: int) -> None:
    if total <= 0:
        return
    pct = min(100, (100 * done) // total)
    print(f"\r  ⋯ {label}: {done}/{total} ({pct}%)", end="", flush=True)
    if done >= total:
        print()


def is_valid_hostname(host: str) -> bool:
    """True if host is a plausible DNS name for getaddrinfo (IDNA-safe)."""
    if not host or len(host) > _MAX_HOSTNAME_LEN or ".." in host:
        return False
    labels = host.split(".")
    if any(not label or len(label) > _MAX_LABEL_LEN for label in labels):
        return False
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    try:
        host.encode("idna")
    except UnicodeError:
        return False
    return True


def is_in_scope(host: str, domain: str) -> bool:
    """Host belongs to target domain (e.g. foo.google.com.br matches google.com)."""
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    if host == domain:
        return True
    padded = "." + host + "."
    needle = "." + domain + "."
    return padded.endswith(needle) or needle in padded


def sanitize_hostname(name: str, domain: str) -> str | None:
    """
    Normalize crt.sh / subfinder output; drop wildcards, junk, and out-of-scope names.
    Returns lowercase hostname or None if unusable.
    """
    if not name or not isinstance(name, str):
        return None
    name = name.strip().lower().rstrip(".")
    if not name or name.startswith("*") or "@" in name:
        return None
    if any(c in name for c in " /:;,\\<>\"'()[]{}|"):
        return None
    domain = domain.strip().lower().rstrip(".")
    if not is_in_scope(name, domain):
        return None
    if not is_valid_hostname(name):
        return None
    return name


# ── Phase 1: crt.sh + subfinder ───────────────────────────────────────────

_log_lock = threading.Lock()


def _log(msg: str) -> None:
    with _log_lock:
        print(msg, flush=True)


def _crt_sh_probe(domain: str) -> tuple[bool, str]:
    """
    Fast liveness check: exact-match CT query (tiny payload vs full %.domain dump).
    Returns (reachable, error_detail).
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        req = Request(
            url,
            headers={"User-Agent": f"D1gger/{__version__} (crt.sh probe)"},
        )
        with urlopen(req, timeout=CRT_SH_PROBE_TIMEOUT_S) as resp:
            chunk = resp.read(CRT_SH_PROBE_READ_BYTES)
        if not chunk.strip():
            return False, "empty response"
        return True, ""
    except TimeoutError:
        return False, f"no response within {CRT_SH_PROBE_TIMEOUT_S}s"
    except HTTPError as e:
        if e.code in CRT_GATEWAY_ERRORS:
            return False, f"HTTP {e.code} (gateway)"
        return False, f"HTTP {e.code}"
    except URLError as e:
        reason = getattr(e, "reason", e)
        return False, str(reason)
    except OSError as e:
        return False, str(e)


def fetch_crt_subdomains(domain) -> set[str]:
    """
    Query crt.sh. Returns hostnames (empty set if unavailable or errored).
    Probes first (~6s); full wildcard fetch only when the probe succeeds.
    """
    _log(f"  [crt.sh] checking service ({CRT_SH_PROBE_TIMEOUT_S}s probe)…")
    ok, err = _crt_sh_probe(domain)
    if not ok:
        _log(f"  [crt.sh] unavailable ({err})")
        return set()

    _log(f"  [crt.sh] fetching %.{domain} (up to {CRT_SH_FETCH_TIMEOUT_S}s)…")
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        req = Request(
            url,
            headers={"User-Agent": f"D1gger/{__version__} (crt.sh fetch)"},
        )
        with urlopen(req, timeout=CRT_SH_FETCH_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode())
    except TimeoutError:
        _log(f"  [crt.sh] fetch timed out after {CRT_SH_FETCH_TIMEOUT_S}s")
        return set()
    except HTTPError as e:
        if e.code in CRT_GATEWAY_ERRORS:
            _log(f"  [crt.sh] HTTP {e.code} (gateway)")
        else:
            _log(f"  [crt.sh] HTTP error {e.code}: {e}")
        return set()
    except URLError as e:
        _log(f"  [crt.sh] request failed: {e}")
        return set()
    except json.JSONDecodeError:
        _log("  [crt.sh] invalid JSON — likely overloaded")
        return set()

    subdomains: set[str] = set()
    skipped = 0
    for record in data:
        for name in record.get("name_value", "").split("\n"):
            host = sanitize_hostname(name, domain)
            if host:
                subdomains.add(host)
            elif name.strip():
                skipped += 1

    if skipped:
        _log(f"  [crt.sh] skipped {skipped} invalid/out-of-scope names")
    _log(f"  [crt.sh] {len(subdomains)} hosts")
    return subdomains


def fetch_subfinder_subdomains(domain) -> set[str]:
    """Enumerate subdomains with ProjectDiscovery subfinder CLI."""
    _log(f"  [subfinder] running for {domain}…")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=900,
        )
    except FileNotFoundError:
        _log(
            "  [subfinder] not on PATH — install from "
            "https://github.com/projectdiscovery/subfinder"
        )
        return set()
    except subprocess.TimeoutExpired:
        _log("  [subfinder] timed out (>15m)")
        return set()

    if result.returncode != 0:
        err = (result.stderr or "").strip() or "(no stderr)"
        _log(f"  [subfinder] exited {result.returncode}: {err[:500]}")
        return set()

    subdomains: set[str] = set()
    for line in result.stdout.splitlines():
        host = sanitize_hostname(line, domain)
        if host:
            subdomains.add(host)
    if sanitize_hostname(domain, domain):
        subdomains.add(domain.lower().rstrip("."))

    _log(f"  [subfinder] {len(subdomains)} hosts")
    return subdomains


def harvest_subdomains(domain, use_subfinder: bool = True) -> set[str]:
    """
    Collect subdomains from crt.sh and subfinder concurrently, then merge.
    If crt.sh is down, results come from subfinder only (when enabled).
    """
    if use_subfinder:
        _log("  ⋯ harvesting from crt.sh and subfinder in parallel…")
        sys.stdout.flush()
        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_crt = pool.submit(fetch_crt_subdomains, domain)
            fut_sf = pool.submit(fetch_subfinder_subdomains, domain)
            crt_hosts = fut_crt.result()
            sf_hosts = fut_sf.result()
    else:
        _log("  ⋯ harvesting from crt.sh only (--no-subfinder)…")
        sys.stdout.flush()
        crt_hosts = fetch_crt_subdomains(domain)
        sf_hosts = set()

    merged = crt_hosts | sf_hosts
    overlap = len(crt_hosts & sf_hosts)

    if crt_hosts and sf_hosts:
        _log(
            f"  [✓] merged {len(merged)} unique "
            f"(crt.sh {len(crt_hosts)}, subfinder {len(sf_hosts)}, overlap {overlap})"
        )
    elif sf_hosts and not crt_hosts:
        _log(f"  [✓] merged {len(merged)} unique (crt.sh unavailable — subfinder only)")
    elif crt_hosts and not sf_hosts:
        _log(f"  [✓] merged {len(merged)} unique (crt.sh only — subfinder added nothing)")
    elif not use_subfinder and crt_hosts:
        _log(f"  [✓] {len(merged)} hosts from crt.sh")
    elif not merged:
        _log("  [!] no hosts from crt.sh or subfinder")

    return merged


# ── Phase 2: DNS Resolution ────────────────────────────────────────────────

def resolve_subdomain(subdomain):
    if not is_valid_hostname(subdomain):
        return []
    try:
        results = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        return ips
    except (socket.gaierror, UnicodeError, OSError):
        return []

def get_dns_records(domain):
    """Pull TXT, MX, NS records using dig for third-party service discovery"""
    print(f"  ⋯ dig TXT/MX/NS/CNAME for {domain}…")
    sys.stdout.flush()
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

def _resolve_task(sub: str) -> tuple[str, list[str] | None]:
    """Resolve one host; None = invalid hostname, [] = NXDOMAIN/dead."""
    if not is_valid_hostname(sub):
        return sub, None
    return sub, resolve_subdomain(sub)


def resolve_all(subdomains, workers: int = DEFAULT_WORKERS, quiet: bool = False):
    hosts = sorted(subdomains)
    total = len(hosts)
    print(f"  ⋯ resolving {total} hostnames ({workers} workers)…")
    sys.stdout.flush()
    resolved: dict[str, list[str]] = {}
    dead: list[str] = []
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_resolve_task, sub): sub for sub in hosts}
        for future in as_completed(futures):
            sub, ips = future.result()
            done += 1
            _progress("DNS", done, total)
            if ips is None:
                dead.append(sub)
                if not quiet:
                    print(f"  [!] skip invalid hostname: {sub[:120]}{'…' if len(sub) > 120 else ''}")
            elif ips:
                resolved[sub] = ips
                if not quiet:
                    print(f"  [✓] {sub} → {', '.join(ips)}")
            else:
                dead.append(sub)

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

def _probe_task(subdomain: str, ips: list[str]) -> tuple[str, list[str], dict]:
    return subdomain, ips, http_probe(subdomain)


def probe_all(resolved, workers: int = DEFAULT_WORKERS, quiet: bool = False):
    items = list(resolved.items())
    total = len(items)
    print(f"  ⋯ probing {total} live hosts via HTTPS/HTTP ({workers} workers)…")
    sys.stdout.flush()
    probed: dict[str, dict] = {}
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_probe_task, sub, ips): sub for sub, ips in items
        }
        for future in as_completed(futures):
            subdomain, ips, http_data = future.result()
            probed[subdomain] = {"ips": ips, "http": http_data}
            done += 1
            _progress("HTTP", done, total)
            if not quiet:
                https_status = http_data.get("https", {}).get("status", "-")
                http_status = http_data.get("http", {}).get("status", "-")
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

def detect_third_parties(dns_records, subdomains, quiet: bool = False):
    print("  ⋯ scanning DNS and hostnames for known third-party signatures…")
    sys.stdout.flush()
    findings = []

    all_text = " ".join(
        str(v) for values in dns_records.values() for v in values
    ).lower() + " " + " ".join(subdomains).lower()

    for keyword, description in THIRD_PARTY_SIGNATURES.items():
        if keyword in all_text:
            findings.append((keyword, description))
            if not quiet:
                print(f"  [!] {keyword.capitalize()} detected — {description}")

    if not findings:
        print("  [-] No known third-party signatures detected in DNS")
    elif quiet:
        names = ", ".join(k.capitalize() for k, _ in findings)
        print(f"  [✓] Detected: {names}")

    return findings

# ── Phase 5: Triage & Scoring ─────────────────────────────────────────────

INTERESTING_KEYWORDS = [
    "admin", "api", "staging", "dev", "test", "internal",
    "data", "load", "infra", "backend", "dashboard", "cms",
    "auth", "login", "frontegg", "meet", "upload", "beta"
]

def triage(probed, quiet: bool = False, top_n: int = 15):
    print("  ⋯ scoring and ranking live targets…")
    sys.stdout.flush()
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

    show = 5 if quiet else top_n
    print("\n  TOP TARGETS (by interest score):")
    print(f"  {'Subdomain':<40} {'HTTPS':>6} {'Score':>6}  Notes")
    print("  " + "-" * 90)
    for item in scored[:show]:
        print(f"  {item['subdomain']:<40} {item['https_status']:>6} {item['score']:>6}  {item['notes']}")

    return scored

# ── Output ─────────────────────────────────────────────────────────────────

def save_output(domain, subdomains, resolved, dead, probed, third_parties, scored, output_dir="runs"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{domain.replace('.', '_')}_{timestamp}"

    # Each scan gets its own subdirectory: <output_dir>/<run_id>/
    out = Path(output_dir).expanduser().resolve() / base
    out.mkdir(parents=True, exist_ok=True)

    files = {}

    def _write(name, content):
        p = out / name
        with open(p, "w", encoding="utf-8") as f:
            f.write(content)
        files[name] = p

    _write("subdomains_all.txt",  "\n".join(sorted(subdomains)))
    _write("subdomains_live.txt", "\n".join(sorted(resolved.keys())))
    _write("subdomains_dead.txt", "\n".join(sorted(dead)))

    csv_path = out / "triage.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["subdomain","ips","https_status","http_status","score","notes"])
        writer.writeheader()
        writer.writerows(scored)
    files["triage.csv"] = csv_path

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
    summary_path = out / "summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    files["summary.json"] = summary_path

    width = max(len(n) for n in files)
    print(f"  ⋯ writing artefacts to disk…")
    sys.stdout.flush()
    print(f"\n  [✓] Run saved → {out}")
    for name, path in files.items():
        size = path.stat().st_size
        size_str = f"{size:,} B" if size < 1024 else f"{size/1024:.1f} KB"
        print(f"    {name:<{width}}  {size_str}")

    return base, out


# ── Wipe ─────────────────────────────────────────────────────────────────────

def _artifact_search_roots() -> list[Path]:
    """Directories to look for default artifact folders (cwd + repo root)."""
    roots: list[Path] = []
    seen: set[Path] = set()
    for candidate in (Path.cwd(), Path(__file__).resolve().parent):
        root = candidate.expanduser().resolve()
        if root not in seen:
            seen.add(root)
            roots.append(root)
    return roots


def _collect_artifact_parents(extra_output_dir: str | None = None) -> list[Path]:
    """Resolved parent directories that may contain run subfolders."""
    parents: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.expanduser().resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        parents.append(resolved)

    for root in _artifact_search_roots():
        for name in _ARTIFACT_DIR_NAMES:
            add(root / name)

    env_out = os.environ.get("D1GGER_OUTPUT_DIR")
    if env_out:
        add(Path(env_out))

    if extra_output_dir:
        add(Path(extra_output_dir))

    return parents


def wipe_artifacts(extra_output_dir: str | None = None) -> int:
    """
    Delete all recon run directories (subdirs containing summary.json)
    under known artifact parents. Returns number of runs removed.
    """
    print("\n[+] Wipe: removing recon run artifacts")
    removed_runs = 0
    removed_files = 0

    for parent in _collect_artifact_parents(extra_output_dir):
        if not parent.is_dir():
            continue
        for summary in sorted(parent.glob("*/summary.json")):
            run_dir = summary.parent
            if not run_dir.is_dir():
                continue
            file_count = sum(1 for p in run_dir.rglob("*") if p.is_file())
            try:
                shutil.rmtree(run_dir)
                removed_runs += 1
                removed_files += file_count
                print(f"  [✓] {run_dir}  ({file_count} file{'s' if file_count != 1 else ''})")
            except OSError as e:
                print(f"  [!] could not remove {run_dir}: {e}", file=sys.stderr)

        # Drop empty artifact parent (e.g. runs/ with no runs left)
        try:
            if parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
                print(f"  [✓] removed empty {parent}")
        except OSError:
            pass

    if removed_runs:
        print(f"\n[✓] Wiped {removed_runs} run(s), {removed_files} file(s)")
    else:
        print("\n[-] Nothing to wipe — no run directories found")
    return removed_runs


# ── Startup banner ─────────────────────────────────────────────────────────

_DEFAULT_API_ORIGIN = "http://127.0.0.1:8765"

_LOGO_ART = r"""
 _______     __
|       \  _/  \
| $$$$$$$\|   $$   ______    ______    ______    ______
| $$  | $$ \$$$$  /      \  /      \  /      \  /      \
| $$  | $$  | $$ |  $$$$$$\|  $$$$$$\|  $$$$$$\|  $$$$$$\
| $$  | $$  | $$ | $$  | $$| $$  | $$| $$    $$| $$   \$$
| $$__/ $$ _| $$_| $$__| $$| $$__| $$| $$$$$$$$| $$
| $$    $$|   $$ \\$$    $$ \$$    $$ \$$     \| $$
 \$$$$$$$  \$$$$$$_\$$$$$$$ _\$$$$$$$  \$$$$$$$ \$$
                 |  \__| $$|  \__| $$
                  \$$    $$ \$$    $$
                   \$$$$$$   \$$$$$$
""".strip("\n").split("\n")

_AGENT_FLOW = [
    "GET  /api/health",
    "POST /api/scan",
    "GET  /api/runs",
    "GET  /api/runs/{run_id}/summary",
    "GET  /api/runs/{run_id}/llm.txt",
    "GET  /api/runs/{run_id}/section/triage/table",
]


def _agent_url_panel(agent_url: str) -> list[str]:
    label = "Agent manifest"
    hint = "▲  point external agents here (e.g. hackfast.co)"
    rows = [agent_url, f"      {hint}"]
    inner = max(68, max(len(r) for r in rows) + 2)
    lines = [f"       ╭─ {label} " + "─" * max(1, inner - len(label) - 1) + "╮"]
    for row in rows:
        pad = max(0, inner - len(row))
        lines.append(f"       │  {row}{' ' * pad}│")
    lines.append(f"       ╰{'─' * (inner + 2)}╯")
    return lines


def print_startup_banner(
    *,
    api_origin: str = _DEFAULT_API_ORIGIN,
    output_dir: str = "runs",
) -> None:
    """Full header when d1gg3r.py is run with no domain (CLI + API pointers)."""
    agent_url = f"{api_origin.rstrip('/')}/api/agent"
    rule = "═" * 76
    out = Path(output_dir).expanduser().resolve()
    lines = [
        "",
        rule,
        f"  D1gger v{__version__} — bug bounty recon",
        f"  CLI artefacts: {out}",
        rule,
        "",
        *_LOGO_ART,
        "",
        *_agent_url_panel(agent_url),
        "",
        "  CLI",
        "  ───",
        "  python3 d1gg3r.py target.com              full scan",
        "  python3 d1gg3r.py target.com --quiet      demo-friendly output",
        "  python3 d1gg3r.py target.com --workers 64 parallel DNS + HTTP",
        "  python3 d1gg3r.py --wipe                  remove local run dirs",
        "  python3 d1gg3r.py --help                  all flags",
        "",
        "  Local API (start server first)",
        "  ─────────────────────────────",
        f"  UI:              {api_origin}/",
        f"  API docs:        {api_origin}/docs",
        f"  Agent manifest:  {agent_url}",
        "",
        "  Recommended agent flow",
        "  ──────────────────────",
    ]
    for step in _AGENT_FLOW:
        lines.append(f"    {step}")
    lines.extend(
        [
            "",
            "  Scan via API:",
            f"    curl -N -sS -X POST -H 'Content-Type: application/json' \\",
            f"      -d '{{\"domain\":\"target.com\",\"quiet\":true}}' \\",
            f"      '{api_origin}/api/scan'",
            "",
            "  Only use against in-scope bug bounty targets.",
            rule,
            "",
        ]
    )
    print("\n".join(lines), flush=True)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Bug bounty recon: crt.sh + DNS + HTTP probing",
        epilog="Only use against targets with explicit bug bounty programs.",
    )
    parser.add_argument(
        "domain",
        nargs="?",
        help="Target domain (e.g. target.com); not required with --wipe",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--wipe",
        action="store_true",
        help="Remove all recon run artifacts (runs/, recon-out/, D1GGER_OUTPUT_DIR, etc.)",
    )
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP probing (DNS only)")
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Skip subfinder (crt.sh only for subdomain discovery)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help=f"Parallel workers for DNS and HTTP (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal per-host output; show progress counters and top triage rows",
    )
    parser.add_argument("--output-dir", default="runs", help="Parent directory for scan output (each run gets its own subfolder)")
    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    if args.wipe:
        extra = args.output_dir if args.output_dir != "runs" else None
        wipe_artifacts(extra)
        sys.exit(0)

    if not args.domain:
        print_startup_banner(output_dir=args.output_dir)
        sys.exit(0)

    domain = args.domain.lower().strip()
    quiet = args.quiet
    workers = args.workers
    t0 = time.perf_counter()

    print("=" * 60)
    print(f"  D1gger v{__version__} — {domain}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  For use with explicit bug bounty targets only.")
    print("=" * 60)
    print_phase_roadmap(skip_http=args.no_http)

    phase_start(1, SCAN_PHASES[0][1], SCAN_PHASES[0][2])
    subdomains = harvest_subdomains(domain, use_subfinder=not args.no_subfinder)
    if not subdomains:
        print("[!] No subdomains found. Exiting.")
        sys.exit(1)
    phase_done(f"{len(subdomains)} subdomains discovered")

    phase_start(2, SCAN_PHASES[1][1], SCAN_PHASES[1][2])
    resolved, dead = resolve_all(subdomains, workers=workers, quiet=quiet)
    if not resolved:
        print("[!] No live subdomains found via DNS.")
    phase_done(f"{len(resolved)} live · {len(dead)} dead/unresolved")

    phase_start(3, SCAN_PHASES[2][1], SCAN_PHASES[2][2])
    root_dns = get_dns_records(domain)
    if not quiet:
        for rtype, values in root_dns.items():
            if values:
                print(f"  {rtype}: {' | '.join(values[:3])}")
    else:
        found = [rtype for rtype, values in root_dns.items() if values]
        if found:
            print(f"  [✓] Record types: {', '.join(found)}")
    phase_done("apex DNS records collected")

    phase_start(4, SCAN_PHASES[3][1], SCAN_PHASES[3][2])
    third_parties = detect_third_parties(root_dns, list(subdomains), quiet=quiet)
    phase_done(
        f"{len(third_parties)} third-party signature(s)"
        if third_parties
        else "no known third-party signatures"
    )

    phase_start(5, SCAN_PHASES[4][1], SCAN_PHASES[4][2])
    if not args.no_http and resolved:
        probed = probe_all(resolved, workers=workers, quiet=quiet)
        phase_done(f"{len(probed)} hosts probed")
    else:
        probed = {sub: {"ips": ips, "http": {}} for sub, ips in resolved.items()}
        reason = "--no-http" if args.no_http else "no live hosts"
        print(f"  ⋯ skipped ({reason})")
        phase_done(f"HTTP probing skipped ({reason})")

    phase_start(6, SCAN_PHASES[5][1], SCAN_PHASES[5][2])
    scored = triage(probed, quiet=quiet) if probed else []
    phase_done(f"{len(scored)} targets ranked" if scored else "nothing to rank")

    phase_start(7, SCAN_PHASES[6][1], SCAN_PHASES[6][2])
    save_output(
        domain, subdomains, resolved, dead, probed, third_parties, scored,
        output_dir=args.output_dir,
    )
    phase_done("artefacts written")

    elapsed = time.perf_counter() - t0
    print(f"\n[✓] Recon complete in {elapsed:.1f}s")
    print(f"    {len(subdomains)} subdomains found → {len(resolved)} live")
    print(f"    {len(third_parties)} third-party services detected")
    if scored:
        top = scored[0]
        print(f"    Top target: {top['subdomain']} (score {top['score']}, HTTPS {top['https_status']})")

if __name__ == "__main__":
    main()