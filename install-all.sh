#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANISETTE_DIR="$ROOT/anisette-v3-server"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

step "Installing iCloud Keychain for Linux (icp)"
command -v python3 >/dev/null || die "'python3' not found. Please install it."

if ! python3 -m venv "$ROOT/.venv" 2>/dev/null; then
  warn "python3 -m venv failed (ensurepip may be missing). Trying --without-pip..."
  python3 -m venv --without-pip "$ROOT/.venv"
  if ! "$ROOT/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
    if command -v curl >/dev/null; then
      curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$ROOT/.venv/get-pip.py"
      "$ROOT/.venv/bin/python" "$ROOT/.venv/get-pip.py"
      rm -f "$ROOT/.venv/get-pip.py"
    else
      die "pip not available in venv and curl not found to bootstrap it."
    fi
  fi
fi

"$ROOT/.venv/bin/pip" install --upgrade pip >/dev/null
"$ROOT/.venv/bin/pip" install -e "$ROOT"
chmod +x "$ROOT/host/icp-host.sh" "$ROOT/host/install.sh"

step "Setting up anisette-v3-server (local Anisette v3, D)"
if [[ ! -d "$ANISETTE_DIR" ]]; then
  die "anisette-v3-server/ not found in $ROOT"
fi

if command -v docker >/dev/null; then
  info "Docker detected. You can run the server with:"
  info "  docker run -d --restart unless-stopped --name anisette-v3 -p 6969:6969 -v anisette-v3_data:/home/Alcoholic/.config/anisette-v3/lib/ dadoum/anisette-v3-server"
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx anisette-v3; then
    info "Container 'anisette-v3' is already running."
  else
    warn "Container 'anisette-v3' is not running. Start it with the command above if needed."
  fi
elif command -v dub >/dev/null && command -v ldc2 >/dev/null; then
  info "Building anisette-v3-server with dub/ldc2..."
  (cd "$ANISETTE_DIR" && DC=ldc2 dub build -c "static" --build-mode allAtOnce -b release --compiler=ldc2)
else
  warn "Neither Docker nor dub+ldc2 found. See anisette-v3-server/README.md for setup options."
fi

step "Done"
printf '\n\033[32m✓ Setup complete.\033[0m\n\n'
printf 'iCloud Keychain for Linux (icp):\n'
printf '  Activate: source %s/.venv/bin/activate\n' "$ROOT"
printf '  Login:    export ICP_ANISETTE_URL="http://localhost:6969" && icp login\n'
printf '  Browser host: %s/host/install.sh [CHROME_EXTENSION_ID]\n\n' "$ROOT"
printf 'anisette-v3-server (local Anisette v3):\n'
printf '  Ensure it is running on http://localhost:6969 and set ICP_ANISETTE_URL accordingly.\n\n'
