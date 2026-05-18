#!/usr/bin/env python3
"""
Local API + web UI: a human visualiser for live recon, plus HTTP resources for
automated agents (e.g. hackfast.co) — runs, section text, triage JSON, LLM bundle.

Run (from repo root, scan current directory):
  pip install -r requirements.txt
  python3 server.py --output-dir /path/to/out
or:
  D1GGER_OUTPUT_DIR=/path/to/out python3 -m uvicorn server:app --host 127.0.0.1 --port 8765

On startup the server prints UI, API docs, and the agent manifest URL — point external
agents (e.g. hackfast.co) at GET /api/agent on this origin.

Default bind: 127.0.0.1 only — do not expose publicly; outputs may be sensitive.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


SECTIONS = {
    "subdomains_all": ("subdomains_all.txt", "text/plain; charset=utf-8"),
    "subdomains_live": ("subdomains_live.txt", "text/plain; charset=utf-8"),
    "subdomains_dead": ("subdomains_dead.txt", "text/plain; charset=utf-8"),
    "triage": ("triage.csv", "text/csv; charset=utf-8"),
    "summary": ("summary.json", "application/json; charset=utf-8"),
}


class ScanBody(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    no_http: bool = False
    no_subfinder: bool = False
    workers: int = Field(default=32, ge=1, le=256)
    quiet: bool = False


def validate_hostname(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if len(d) < 3 or len(d) > 253 or ".." in d:
        raise HTTPException(status_code=400, detail="Invalid domain")
    if not re.fullmatch(r"[a-z0-9_.-]+", d):
        raise HTTPException(status_code=400, detail="Invalid domain (allowed: a-z, 0-9, hyphen, underscore, dots)")
    if "." not in d:
        raise HTTPException(status_code=400, detail="Invalid domain — include a hostname with a dot")
    return d


def sse_json(obj: dict) -> bytes:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode("utf-8")


def validate_run_id(run_id: str) -> str:
    if not run_id:
        raise ValueError("Invalid run id")
    if ".." in run_id or "/" in run_id or "\\" in run_id:
        raise ValueError("Invalid run id")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise ValueError("Invalid run id")
    return run_id


def _safe_run_id(run_id: str) -> str:
    try:
        return validate_run_id(run_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


def iter_runs(output_dir: Path):
    """Yield (run_id, summary_path) for every run dir, newest first."""
    runs = []
    for p in output_dir.glob("*/summary.json"):
        runs.append((p.stat().st_mtime, p.parent.name, p))
    for _, run_id, p in sorted(runs, reverse=True):
        yield run_id, p


def run_dir(output_dir: Path, run_id: str) -> Path:
    rid = _safe_run_id(run_id)
    d = output_dir / rid
    if not d.is_dir():
        raise HTTPException(404, "Run not found")
    return d


def summary_path(output_dir: Path, run_id: str) -> Path:
    d = run_dir(output_dir, run_id)
    p = d / "summary.json"
    if not p.is_file():
        raise HTTPException(404, "Run not found")
    return p


def section_path(output_dir: Path, run_id: str, section: str) -> tuple[Path, str]:
    if section not in SECTIONS:
        raise HTTPException(400, f"Unknown section. Use one of: {', '.join(SECTIONS)}")
    filename, ctype = SECTIONS[section]
    d = run_dir(output_dir, run_id)
    path = d / filename
    if not path.is_file():
        raise HTTPException(404, f"Section file missing for this run: {section}")
    return path, ctype


def build_llm_bundle(output_dir: Path, run_id: str) -> str:
    rid = validate_run_id(run_id)
    d = output_dir / rid
    if not d.is_dir():
        raise FileNotFoundError(d)
    summary_p = d / "summary.json"
    if not summary_p.is_file():
        raise FileNotFoundError(summary_p)
    with open(summary_p, encoding="utf-8") as f:
        summary = json.load(f)

    lines = [
        "D1gger recon bundle (for LLM / agent consumption)",
        f"run_id: {rid}",
        f"target: {summary.get('target', '?')}",
        f"timestamp: {summary.get('timestamp', '?')}",
        "",
    ]

    order = [
        ("summary", "Summary (JSON, pretty-printed)"),
        ("subdomains_all", "All subdomains (crt.sh + subfinder, merged)"),
        ("subdomains_live", "DNS-resolved (live)"),
        ("subdomains_dead", "DNS dead / unresolved"),
        ("triage", "Triage CSV"),
    ]

    for key, title in order:
        filename, _ctype = SECTIONS[key]
        p = d / filename
        if not p.is_file():
            lines += [f"## {title}", "(file not present)", ""]
            continue
        body = p.read_text(encoding="utf-8", errors="replace")
        if key == "summary":
            try:
                body = json.dumps(json.loads(body), indent=2)
            except json.JSONDecodeError:
                pass
        lines += [f"## {title}", f"file: {p.name}", "", body.rstrip(), ""]
    return "\n".join(lines).rstrip() + "\n"


def create_app(output_dir: Path) -> FastAPI:
    output_dir = output_dir.expanduser().resolve()
    repo_root = Path(__file__).resolve().parent
    d1gger_script = repo_root / "d1gg3r.py"
    scan_busy = threading.Event()

    app = FastAPI(
        title="D1gger local API",
        description=(
            "Visualiser backend: stream scans, list runs, expose artifacts. "
            "Use GET /api/agent for agent integration. "
            f"Artifact directory: {output_dir}"
        ),
        version="1.2.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health():
        return {"ok": True, "output_dir": str(output_dir), "scan_busy": scan_busy.is_set()}

    @app.get("/api/agent")
    def agent_manifest():
        """
        Stable JSON for external agents: hackfast.co and similar tools should
        start here, then follow `recommended_flow`.
        """
        return {
            "service": "d1gger-local",
            "version": "1.2.0",
            "product_name": "D1gger",
            "what_it_does": (
                "Local bug-bounty recon for a domain you supply: subdomain discovery runs crt.sh and subfinder "
                "in parallel (merged; subfinder-only if crt.sh is down), then seven phases — parallel IPv4 DNS, "
                "apex DNS records, third-party hints, parallel HTTPS/HTTP probing, scored triage, and artifacts "
                "under artifact_directory — exposed via this HTTP API and a browser UI at /."
            ),
            "scan_pipeline": [
                "1 Subdomain discovery — crt.sh + subfinder in parallel (merged)",
                "2 DNS resolution — parallel IPv4 per hostname",
                "3 Apex DNS records — TXT, MX, NS, CNAME on root domain",
                "4 Third-party detection — SaaS/CDN keyword hints",
                "5 HTTP probing — parallel HTTPS/HTTP (skipped when no_http)",
                "6 Triage & scoring — rank targets by name + status",
                "7 Save artifacts — runs/<run_id>/ txt, csv, json",
            ],
            "scan_body": {
                "domain": "required — in-scope target hostname",
                "no_http": "skip phase 5 HTTP probing",
                "no_subfinder": "crt.sh only for phase 1 (no subfinder)",
                "workers": "parallel workers for DNS + HTTP (default 32)",
                "quiet": "minimal per-host log noise; progress counters still stream",
            },
            "purpose": {
                "human": "Browser visualiser at '/' (live scan + run snapshot + tables).",
                "agent": (
                    "Structured HTTP access to the same recon artifacts the UI shows; "
                    "no authentication on default localhost binding — bind 127.0.0.1 only."
                ),
            },
            "artifact_directory": str(output_dir),
            "discovery": {
                "this_manifest": "GET /api/agent",
                "openapi": "GET /docs",
                "json_meta": "GET /api/meta",
            },
            "recommended_flow": [
                "GET /api/health — confirm output_dir and whether a scan is running",
                "POST /api/scan — start recon (SSE stream; see executor_notes.scan_sse_semantics)",
                "GET /api/runs — list recon runs (newest first)",
                "GET /api/runs/{run_id}/summary — JSON rollup (counts, third_parties, top_targets)",
                "GET /api/runs/{run_id}/sections — which section files exist + relative URLs",
                "GET /api/runs/{run_id}/llm.txt — one plain-text document with all sections",
                "GET /api/runs/{run_id}/section/triage/table — triage as rows/columns JSON",
                "GET /api/runs/{run_id}/section/{section}/text — UTF-8 slice (summary = pretty JSON)",
            ],
            "sections": list(SECTIONS.keys()),
            "executor_notes": {
                "unix_shell_http": (
                    '"GET http://host/path" is not a shell command. Always call HTTP with a client '
                    "(e.g. curl -sS 'http://host/path'). Commands like `GET …` alone will fail with "
                    "'command not found'."
                ),
                "post_json_body": (
                    "POST /api/scan expects one JSON object in the HTTP body — not a string containing JSON. "
                    "Do not double-escape quotes. Example curl flag: "
                    '-d \'{"domain":"target.com","no_http":false,"no_subfinder":false,'
                    '"workers":32,"quiet":true}\' '
                    "with Content-Type: application/json."
                ),
                "subdomain_discovery": (
                    "Phase 1 runs crt.sh and subfinder concurrently and merges results. "
                    "If crt.sh is unreachable, the scan continues with subfinder output only."
                ),
                "scan_sse_semantics": (
                    "POST /api/scan returns SSE: parse lines prefixed with data: as JSON objects. "
                    "Stop after type is done. exit_code is 0 only on success; run_id is the "
                    "*_summary.json stem only when artifacts were saved. "
                    "If exit_code is not 0 or run_id is null, nothing new was written — "
                    "GET /api/runs still lists prior successful runs to read."
                ),
                "scan_domain_realism": (
                    "Use a real in-scope bounty domain — placeholder hostnames often yield no CT data "
                    "and exit before saving (no run_id)."
                ),
            },
            "copy_paste_shell": {
                "replace_REPLACE_BASE_with_server_origin": True,
                "list_runs": "curl -sS 'REPLACE_BASE/api/runs'",
                "trigger_scan_sse": (
                    "curl -N -sS -X POST -H 'Content-Type: application/json' "
                    '-d \'{"domain":"target.com","no_http":false,"no_subfinder":false,'
                    '"workers":32,"quiet":true}\' '
                    "'REPLACE_BASE/api/scan'"
                ),
                "pull_summary_after_runKNOWN_ID": (
                    "curl -sS 'REPLACE_BASE/api/runs/KNOWN_RUN_ID/summary'"
                ),
            },
            "endpoints": {
                "scan_sse": "POST /api/scan",
                "runs": "GET /api/runs",
                "run_summary": "GET /api/runs/{run_id}/summary",
                "run_sections": "GET /api/runs/{run_id}/sections",
                "section_raw": "GET /api/runs/{run_id}/section/{section}/raw",
                "section_text": "GET /api/runs/{run_id}/section/{section}/text",
                "triage_table": "GET /api/runs/{run_id}/section/triage/table",
                "llm_bundle": "GET /api/runs/{run_id}/llm.txt",
            },
        }

    @app.post("/api/scan")
    def launch_scan(body: ScanBody):
        """
        Run d1gg3r.py against the configured output dir; response is an SSE stream:
        events {type: start|log|error|done}, done includes exit_code and run_id when detected.
        """
        if scan_busy.is_set():
            raise HTTPException(
                status_code=409,
                detail="Another scan is already running — wait for it to finish.",
            )
        if not d1gger_script.is_file():
            raise HTTPException(
                status_code=500,
                detail=f"d1gg3r.py not found at {d1gger_script}",
            )
        domain = validate_hostname(body.domain)

        def event_stream():
            scan_busy.set()
            proc = None
            try:
                yield sse_json({"type": "start", "domain": domain, "output_dir": str(output_dir)})
                cmd = [
                    sys.executable,
                    "-u",
                    str(d1gger_script),
                    domain,
                    "--output-dir",
                    str(output_dir),
                ]
                if body.no_http:
                    cmd.append("--no-http")
                if body.no_subfinder:
                    cmd.append("--no-subfinder")
                cmd.extend(["--workers", str(body.workers)])
                if body.quiet:
                    cmd.append("--quiet")
                env = {**os.environ, "PYTHONUNBUFFERED": "1"}
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    cwd=str(repo_root),
                    env=env,
                )
                run_id_seen = None
                assert proc.stdout is not None
                for line in proc.stdout:
                    text = line.rstrip("\n\r")
                    yield sse_json({"type": "log", "line": text})
                    # "Run saved → /abs/path/runs/<run_id>"
                    m = re.search(r"Run saved.*?[/\\]([\w.-]+)\s*$", line)
                    if m:
                        run_id_seen = m.group(1)
                proc.stdout.close()
                code = proc.wait()
                yield sse_json(
                    {
                        "type": "done",
                        "exit_code": code,
                        "run_id": run_id_seen,
                    }
                )
            except Exception as e:
                yield sse_json({"type": "error", "message": repr(e)})
                yield sse_json({"type": "done", "exit_code": 1, "run_id": None})
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                scan_busy.clear()

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/api/runs")
    def list_runs():
        out = []
        for run_id, path in iter_runs(output_dir):
            try:
                with open(path, encoding="utf-8") as f:
                    summ = json.load(f)
            except (OSError, json.JSONDecodeError):
                summ = {}
            out.append(
                {
                    "run_id": run_id,
                    "target": summ.get("target"),
                    "timestamp": summ.get("timestamp"),
                    "subdomains_found": summ.get("subdomains_found"),
                    "subdomains_live": summ.get("subdomains_live"),
                    "summary_path": path.name,
                }
            )
        return {"runs": out, "output_dir": str(output_dir)}

    @app.get("/api/runs/{run_id}/summary")
    def run_summary_json(run_id: str):
        """Parsed *_summary.json — same data the visualiser uses for the run snapshot."""
        path = summary_path(output_dir, run_id)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=500, detail="Corrupt summary JSON") from e

    @app.get("/api/runs/{run_id}/sections")
    def run_sections(run_id: str):
        d = run_dir(output_dir, run_id)
        files = {}
        for key, (filename, ctype) in SECTIONS.items():
            p = d / filename
            files[key] = {
                "present": p.is_file(),
                "filename": filename if p.is_file() else None,
                "content_type": ctype,
                "urls": {
                    "raw": f"/api/runs/{run_id}/section/{key}/raw",
                    "text": f"/api/runs/{run_id}/section/{key}/text",
                },
            }
        return {"run_id": run_id, "sections": files}

    @app.get("/api/runs/{run_id}/section/{section}/raw")
    def section_raw(run_id: str, section: str):
        path, ctype = section_path(output_dir, run_id, section)
        return FileResponse(path, media_type=ctype, filename=path.name)

    @app.get("/api/runs/{run_id}/section/{section}/text", response_class=PlainTextResponse)
    def section_text(run_id: str, section: str):
        path, _ = section_path(output_dir, run_id, section)
        if section == "summary":
            obj = json.loads(path.read_text(encoding="utf-8"))
            return json.dumps(obj, indent=2)
        return path.read_text(encoding="utf-8", errors="replace")

    @app.get("/api/runs/{run_id}/section/triage/table")
    def triage_table(run_id: str):
        """Triage CSV as JSON for the web UI table."""
        path, _ = section_path(output_dir, run_id, "triage")
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            cols = list(reader.fieldnames or [])
            rows = [dict(row) for row in reader]
        return {"run_id": run_id, "columns": cols, "rows": rows}

    @app.get("/api/runs/{run_id}/llm.txt", response_class=PlainTextResponse)
    def llm_txt(run_id: str):
        """Single plaintext document with all sections for agent/LLM context."""
        try:
            txt = build_llm_bundle(output_dir, run_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Run not found") from None
        rid = validate_run_id(run_id)
        return PlainTextResponse(
            txt,
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": f'inline; filename="{rid}_llm_bundle.txt"'
            },
        )

    @app.get("/api/meta")
    def api_meta():
        return {
            "sections": list(SECTIONS.keys()),
            "agent_manifest": "GET /api/agent",
            "endpoints": {
                "scan": "POST /api/scan (SSE stream)",
                "runs": "GET /api/runs",
                "run_summary": "GET /api/runs/{run_id}/summary",
                "run_sections": "GET /api/runs/{run_id}/sections",
                "section_raw": "GET /api/runs/{run_id}/section/{section}/raw",
                "section_text": "GET /api/runs/{run_id}/section/{section}/text",
                "triage_table": "GET /api/runs/{run_id}/section/triage/table",
                "llm_bundle": "GET /api/runs/{run_id}/llm.txt",
            },
            "section_descriptions": {
                "subdomains_all": "All discovered hostnames (crt.sh + subfinder, merged)",
                "subdomains_live": "Hosts that resolved in DNS",
                "subdomains_dead": "Names that did not resolve",
                "triage": "Per-host scoring CSV",
                "summary": "JSON rollup with counts and third parties",
            },
        }

    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.is_dir():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


DEFAULT_OUTPUT_DIR = Path(os.environ.get("D1GGER_OUTPUT_DIR", "."))
app = create_app(DEFAULT_OUTPUT_DIR)


def _origin(host: str, port: int) -> str:
    if host in ("0.0.0.0", "::"):
        return f"http://127.0.0.1:{port}"
    scheme = "https" if port == 443 else "http"
    if ":" in host and host.startswith("["):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}:{port}"


def _agent_url_panel(agent_url: str) -> list[str]:
    """Framed agent URL line; width follows URL length."""
    label = "Agent manifest"
    hint = "▲  point external agents here (e.g. hackfast.co)"
    rows = [agent_url, f"      {hint}"]
    inner = max(68, max(len(r) for r in rows) + 2)
    lines = [
        f"       ╭─ {label} " + "─" * max(1, inner - len(label) - 1) + "╮",
    ]
    for row in rows:
        pad = max(0, inner - len(row))
        lines.append(f"       │  {row}{' ' * pad}│")
    lines.append(f"       ╰{'─' * (inner + 2)}╯")
    return lines


def _startup_logo_art(agent_url: str) -> list[str]:
    logo = r"""
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
    return [""] + logo + [""] + _agent_url_panel(agent_url) + [""]


def _print_startup_banner(origin: str, output_dir: Path) -> None:
    agent_url = f"{origin}/api/agent"
    rule = "═" * 76
    lines = [
        "",
        rule,
        "  D1gger local API",
        f"  Artefacts: {output_dir.resolve()}",
        rule,
        "",
        *_startup_logo_art(agent_url),
        "",
        f"  UI:              {origin}/",
        f"  API docs:        {origin}/docs",
        "",
        "  Only use against in-scope bug bounty targets.",
        rule,
        "",
    ]
    print("\n".join(lines), flush=True)


def main():
    parser = argparse.ArgumentParser(description="D1gger local API server")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory containing *_summary.json and related artefact files",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address")
    parser.add_argument("--port", type=int, default=8765, help="Port")
    args = parser.parse_args()

    out = Path(args.output_dir).expanduser().resolve()
    origin = _origin(args.host, args.port)
    _print_startup_banner(origin, out)

    app = create_app(out)

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
