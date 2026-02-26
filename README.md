# Collector of Collectors (V2Ray)

Fetches multiple V2Ray subscription sources, merges and deduplicates configs (protocol-aware), tests them with Xray, and serves results via FastAPI.

## Features
- Collects source URLs from `collectors.txt`
- Handles plain-text and base64 subscription responses
- Deduplicates `vmess/vless/trojan/ss/ssr/hysteria/hysteria2` by normalized config properties (not remarks/name)
- Tests configs in batches using Xray + one request to `https://www.google.com/generate_204`
- Serves output files as plain text:
  - `/collection-of-collector.txt`
  - `/collection-of-collectors-working.txt`
- Can auto-commit and push generated output files to GitHub after each successful cycle

## Requirements
- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- `xray` available in PATH, or set `XRAY_BIN` in `.env`
- `git` configured if using auto-push (`.git` repo + SSH-accessible remote)

## Setup (uv)
1. Copy config template:
   ```bash
   cp .env.example .env
   ```
2. Sync dependencies:
   ```bash
   uv sync
   ```
3. Run server:
   ```bash
   uv run python main.py
   ```

## Install as systemd Service
```bash
./scripts/install_systemd_service.sh
```

Optional flags:
- `--service-name collector-of-collectors-v2ray`
- `--project-dir /absolute/path/to/repo`
- `--user your-linux-user`

## Configuration
All runtime values are in `.env`:
- collection interval
- fetch timeout
- batch size and test timeout
- optional hard batch timeout via `TEST_BATCH_TIMEOUT_SECONDS` (`0` = auto)
- `TEST_TIMEOUT_SECONDS` is a hard per-config deadline (startup + probe + cleanup path)
- Xray startup wait and socks starting port
- output file paths
- host/port for API server
- `RUN_STARTUP_CYCLE` to disable immediate heavy run on boot
- `TEST_MAX_CONFIGS_PER_CYCLE` to cap how many proxies are tested per cycle (`0` = no limit)
- `GIT_AUTO_PUSH_ENABLED` to enable/disable auto commit+push
- `GIT_PUSH_REMOTE` and `GIT_PUSH_BRANCH` to control push target
- `GIT_PUSH_TIMEOUT_SECONDS` for timeout-bounded git commands
- `GIT_COMMIT_AUTHOR_NAME` and `GIT_COMMIT_AUTHOR_EMAIL` for auto-commit identity

## Useful for Large Lists
If you have thousands of proxies and startup feels slow, use:
```env
RUN_STARTUP_CYCLE=false
TEST_MAX_CONFIGS_PER_CYCLE=500
```

## GitHub Auto Push
After a successful cycle, the service can push only these generated files:
- `collection-of-collector.txt`
- `collection-of-collectors-working.txt`

Requirements:
- repository initialized locally (`.git` exists)
- remote configured (default `origin`)
- service user has SSH key permission to push

If repo or remote is missing, the service logs a warning and continues serving/testing.

## Project Structure
- `main.py`: FastAPI app + scheduler
- `collector.py`: fetch + parse + dedup + merged output
- `tester.py`: Xray-based batch testing + working output
- `collectors.txt`: source list input
