# D1gger

Bug-bounty recon for a single domain: subdomain discovery (crt.sh, optional subfinder fallback), parallel DNS resolution, HTTP probing, third-party hints, and a scored triage report. Includes a local web UI and HTTP API for humans and automation agents.

**Only use against targets you are authorized to test** (e.g. in-scope bug bounty programs).

## Requirements

- Python 3.10+
- `curl` and `dig` on your `PATH`
- Optional: [subfinder](https://github.com/projectdiscovery/subfinder) (used when crt.sh is down or times out)

## Install

```bash
git clone https://github.com/atxyy/D1gger.git
cd D1gger
pip install -r requirements.txt
```

## CLI

Run a full scan (artifacts saved under `runs/<run_id>/`):

```bash
python3 d1gg3r.py target.com
```

Options:

```bash
python3 d1gg3r.py target.com --workers 64          # parallel DNS + HTTP (default 32)
python3 d1gg3r.py target.com --quiet               # progress + summary (good for demos)
python3 d1gg3r.py target.com --no-http            # skip HTTP probing
python3 d1gg3r.py target.com --no-subfinder        # crt.sh only (no subfinder)
python3 d1gg3r.py target.com --output-dir ./recon-out
python3 d1gg3r.py --wipe                           # remove all local run artifacts
python3 d1gg3r.py --version
```

### Output layout

Each run creates a folder:

```
runs/target_com_20260518_143022/
  subdomains_all.txt
  subdomains_live.txt
  subdomains_dead.txt
  triage.csv
  summary.json
```

| File | Description |
|------|-------------|
| `subdomains_all.txt` | All discovered hostnames |
| `subdomains_live.txt` | DNS-resolved hosts |
| `subdomains_dead.txt` | Unresolved hostnames |
| `triage.csv` | Per-host score and HTTP status |
| `summary.json` | Counts, third parties, top targets |

## Web UI & API

Start the local server (binds to `127.0.0.1` by default):

```bash
python3 server.py --output-dir ./recon-out
```

On startup you’ll see:

- **UI** — http://127.0.0.1:8765/
- **API docs** — http://127.0.0.1:8765/docs
- **Agent manifest** — http://127.0.0.1:8765/api/agent (point external agents here)

Alternative:

```bash
D1GGER_OUTPUT_DIR=./recon-out python3 -m uvicorn server:app --host 127.0.0.1 --port 8765
```

Use the UI to run scans and browse past runs. Do not expose this server publicly; results can contain sensitive host data.

### Trigger a scan via API

```bash
curl -N -sS -X POST -H 'Content-Type: application/json' \
  -d '{"domain":"target.com","no_http":false,"no_subfinder":false,"workers":32,"quiet":true}' \
  'http://127.0.0.1:8765/api/scan'
```

The response is an SSE stream. List past runs:

```bash
curl -sS 'http://127.0.0.1:8765/api/runs'
```

Pull everything for one run as plain text (handy for LLMs/agents):

```bash
curl -sS 'http://127.0.0.1:8765/api/runs/RUN_ID/llm.txt'
```

See `GET /api/agent` for the full agent integration flow.

## What it does

Each scan runs seven phases (printed at startup):

| Phase | Name | What happens |
|-------|------|----------------|
| 1 | Subdomain discovery | crt.sh + subfinder in parallel, merged (subfinder-only if crt.sh is down) |
| 2 | DNS resolution | parallel IPv4 resolve for every hostname |
| 3 | Apex DNS records | `dig` TXT, MX, NS, CNAME on the root domain |
| 4 | Third-party detection | keyword hints (Stripe, Heroku, Vercel, AWS, etc.) |
| 5 | HTTP probing | parallel HTTPS/HTTP status, redirects, timing (skipped with `--no-http`) |
| 6 | Triage & scoring | rank hosts by interesting names and response codes |
| 7 | Save artifacts | write `runs/<run_id>/` (txt, csv, json) |

## License

MIT — see [LICENSE](LICENSE). Use responsibly and within program rules.

## Changelog

### 1.2.0 — 2026-05-18

- Subdomain discovery runs **crt.sh and subfinder in parallel** and merges both result sets
- If crt.sh is unavailable, scan continues with subfinder output only (no hard failure)
- `--no-subfinder` limits discovery to crt.sh only

### 1.1.0 — 2026-05-18

- Seven-phase scan pipeline with roadmap at startup and per-phase `⋯` loading / `[✓]` done banners
- Progress counters during parallel DNS and HTTP (shown even with `--quiet`)
- Web UI phase rail syncs to `Phase N/7` lines in the scan log
- crt.sh two-step lookup: 6s liveness probe, then 45s wildcard fetch — fail fast (~6s) when crt.sh is down instead of waiting 90s
- README documents all seven phases in a table

### 1.0.0 — 2026-05-18

- Parallel DNS and HTTP probing (`--workers`, default 32)
- `--quiet` for demo-friendly progress output and shorter triage table
- `--wipe` to remove local run artifacts under `runs/`, `recon-out/`, etc.
- `--version` and elapsed-time summary after each scan
- Startup banner when running `python3 d1gg3r.py` with no arguments (ASCII logo, CLI help, agent manifest URLs)
- Per-run output directories: `runs/<run_id>/` with `subdomains_*.txt`, `triage.csv`, `summary.json`
- Local web UI and HTTP API (`server.py`) with SSE scans and `GET /api/agent` manifest
- API scan body supports `workers` and `quiet`
- MIT license; `runs/` and `recon-out/` added to `.gitignore`
