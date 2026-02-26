#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="collector-of-collectors-v2ray"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_USER="${USER}"
APP_GROUP="$(id -gn "${APP_USER}")"
UV_BIN="$(command -v uv || true)"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/install_systemd_service.sh [options]

Options:
  --service-name NAME   systemd service name (default: collector-of-collectors-v2ray)
  --project-dir PATH    project directory (default: repo root)
  --user USER           run service as USER (default: current user)
  -h, --help            show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-name)
      SERVICE_NAME="$2"
      shift 2
      ;;
    --project-dir)
      PROJECT_DIR="$2"
      shift 2
      ;;
    --user)
      APP_USER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${UV_BIN}" ]]; then
  echo "uv is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "WARNING: git is not installed. GitHub auto-push will be skipped by the app."
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required but not found." >&2
  exit 1
fi

if [[ ! -d "${PROJECT_DIR}" ]]; then
  echo "Project directory not found: ${PROJECT_DIR}" >&2
  exit 1
fi

if [[ ! -f "${PROJECT_DIR}/pyproject.toml" ]]; then
  echo "pyproject.toml not found in ${PROJECT_DIR}" >&2
  exit 1
fi

APP_GROUP="$(id -gn "${APP_USER}")"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ ! -f "${PROJECT_DIR}/.env" && -f "${PROJECT_DIR}/.env.example" ]]; then
  cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
  echo "Created ${PROJECT_DIR}/.env from .env.example"
fi

if command -v git >/dev/null 2>&1; then
  if [[ ! -d "${PROJECT_DIR}/.git" ]]; then
    echo "WARNING: ${PROJECT_DIR} is not a git repository (.git missing)."
    echo "         Auto-push is enabled by default but will be skipped."
  elif ! git -C "${PROJECT_DIR}" remote get-url origin >/dev/null 2>&1; then
    echo "WARNING: git remote 'origin' is not configured in ${PROJECT_DIR}."
    echo "         Auto-push will be skipped until a remote is configured."
  else
    echo "Git remote origin detected: $(git -C "${PROJECT_DIR}" remote get-url origin)"
    echo "Ensure user '${APP_USER}' has SSH permission to push."
  fi
fi

echo "Installing dependencies with uv..."
(
  cd "${PROJECT_DIR}"
  "${UV_BIN}" sync
)

echo "Writing systemd unit: ${SERVICE_FILE}"
sudo tee "${SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=Collector of Collectors V2Ray
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${PROJECT_DIR}
EnvironmentFile=-${PROJECT_DIR}/.env
ExecStart=${UV_BIN} run python main.py
Restart=always
RestartSec=5
KillSignal=SIGINT
TimeoutStopSec=25

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd and enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"
sudo systemctl restart "${SERVICE_NAME}"

echo
echo "Service installed and restarted: ${SERVICE_NAME}"
sudo systemctl status "${SERVICE_NAME}" --no-pager --lines=20 || true
