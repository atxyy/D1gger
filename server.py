#!/usr/bin/env python3
"""
Local API + web UI: a human visualiser for live recon, plus HTTP resources for
automated agents (e.g. hackfast.co) — runs, section text, triage JSON, LLM bundle.

Run (from repo root, scan current directory):
  pip install -r requirements.txt
  python3 server.py --output-dir /path/to/out
or:
  D1GGER_OUTPUT_DIR=/path/to/out python3 -m uvicorn server:app --host 127.0.0.1 --port 8765
Then open http://127.0.0.1:8765/ — API docs at /docs .

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
    "subdomains_all": ("_subdomains_all.txt", "text/plain; charset=utf-8"),
    "subdomains_live": ("_subdomains_live.txt", "text/plain; charset=utf-8"),
    "subdomains_dead": ("_subdomains_dead.txt", "text/plain; charset=utf-8"),
    "triage": ("_triage.csv", "text/csv; charset=utf-8"),
    "summary": ("_summary.json", "application/json; charset=utf-8"),
}


class ScanBody(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    no_http: bool = False
    no_subfinder: bool = False


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
    pattern = "*_summary.json"
    for p in sorted(output_dir.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True):
        run_id = p.name[: -len("_summary.json")]
        yield run_id, p


def summary_path(output_dir: Path, run_id: str) -> Path:
    rid = _safe_run_id(run_id)
    path = output_dir / f"{rid}_summary.json"
    if not path.is_file():
        raise HTTPException(404, "Run not found")
    return path


def section_path(output_dir: Path, run_id: str, section: str) -> tuple[Path, str]:
    if section not in SECTIONS:
        raise HTTPException(400, f"Unknown section. Use one of: {', '.join(SECTIONS)}")
    suffix, ctype = SECTIONS[section]
    rid = _safe_run_id(run_id)
    path = output_dir / f"{rid}{suffix}"
    if not path.is_file():
        raise HTTPException(404, f"Section file missing for this run: {section}")
    return path, ctype


def build_llm_bundle(output_dir: Path, run_id: str) -> str:
    rid = validate_run_id(run_id)
    summary_p = output_dir / f"{rid}_summary.json"
    if not summary_p.is_file():
        raise FileNotFoundError(summary_p)
    with open(summary_p, encoding="utf-8") as f:
        summary = json.load(f)
    meta = summary.get("target", "?")
    ts = summary.get("timestamp", "?")

    lines = [
        f"D1gger recon bundle (for LLM / agent consumption)",
        f"run_id: {rid}",
        f"target: {meta}",
        f"timestamp: {ts}",
        "",
    ]

    order = [
        ("summary", "Summary (JSON, pretty-printed)"),
        ("subdomains_all", "All subdomains (crt.sh harvest)"),
        ("subdomains_live", "DNS-resolved (live)"),
        ("subdomains_dead", "DNS dead / unresolved"),
        ("triage", "Triage CSV"),
    ]

    for key, title in order:
        suffix, _ctype = SECTIONS[key]
        p = output_dir / f"{rid}{suffix}"
        if not p.is_file():
            lines.append(f"## {title}")
            lines.append("(file not present)")
            lines.append("")
            continue
        body = p.read_text(encoding="utf-8", errors="replace")
        lines.append(f"## {title}")
        lines.append(f"file: {p.name}")
        lines.append("")
        if key == "summary":
            try:
                obj = json.loads(body)
                body = json.dumps(obj, indent=2)
            except json.JSONDecodeError:
                pass
        lines.append(body.rstrip())
        lines.append("")
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
        version="1.0.0",
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
            "version": "1.0.0",
            "product_name": "D1gger",
            "what_it_does": (
                "Local bug-bounty recon for a domain you supply: subdomain discovery (crt.sh, subfinder fallback), "
                "bulk IPv4 DNS resolution, optional HTTPS/HTTP probing, DNS-based third-party hints, scored triage CSV, "
                "and artifacts written under artifact_directory — all exposed via this HTTP API and a browser UI at /."
            ),
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
                    '-d \'{"domain":"example.com","no_http":false,"no_subfinder":false}\' '
                    "with Content-Type: application/json."
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
                    '-d \'{"domain":"example.com","no_http":false,"no_subfinder":false}\' '
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
                    m = re.search(r"([\w.-]+)_summary\.json\b", line)
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
        summary_path(output_dir, run_id)
        files = {}
        for key, (suffix, ctype) in SECTIONS.items():
            p = output_dir / f"{_safe_run_id(run_id)}{suffix}"
            files[key] = {
                "present": p.is_file(),
                "filename": p.name if p.is_file() else None,
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
                "subdomains_all": "Certificate transparency names (crt.sh)",
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

    out = Path(args.output_dir)
    app = create_app(out)

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
