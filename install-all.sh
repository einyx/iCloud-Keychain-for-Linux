#!/usr/bin/env bash
set -euo pipefail

DMG="${1:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRANOLA_DIR="$ROOT/Granola-for-Linux"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }

step "Initializing submodules"
git -C "$ROOT" submodule update --init --recursive

step "Installing iCloud Keychain for Linux (icp)"
command -v python3 >/dev/null || die "'python3' not found. Please install it."
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install --upgrade pip >/dev/null
"$ROOT/.venv/bin/pip" install -e "$ROOT"
chmod +x "$ROOT/host/icp-host.sh" "$ROOT/host/install.sh"

if [[ -n "$DMG" ]]; then
  step "Installing Granola for Linux"
  "$GRANOLA_DIR/granola-linux.sh" "$DMG"
else
  info "Skipping Granola install (no .dmg path provided)."
  info "To install Granola too: $0 /path/to/Granola.dmg"
fi

step "Done"
printf '\n\033[32m✓ Setup complete.\033[0m\n\n'
printf 'iCloud Keychain for Linux (icp):\n'
printf '  Activate: source %s/.venv/bin/activate\n' "$ROOT"
printf '  Login:    export ICP_ANISETTE_URL="http://localhost:6969" && icp login\n'
printf '  Browser host: %s/host/install.sh [CHROME_EXTENSION_ID]\n\n' "$ROOT"
if [[ -n "$DMG" ]]; then
  printf 'Granola:\n  Installed from the provided .dmg (see output above).\n\n'
else
  printf 'Granola:\n  Skipped. Run: %s/granola-linux.sh "/path/to/Granola.dmg"\n\n' "$GRANOLA_DIR"
fi
