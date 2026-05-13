#!/usr/bin/env bash

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON=$(command -v python3 || command -v python)

if [ -z "$PYTHON" ]; then
  echo "Python is not installed."
  exit 1
fi

cd "$PROJECT_DIR" || exit 1
exec "$PYTHON" "wifi_auditor_ui.py"
