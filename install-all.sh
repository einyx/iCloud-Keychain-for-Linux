#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OMNI_DIR="$ROOT/omnisette-server"

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1;36m==>\033[0m \033[1m%s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }

step "Installing iCloud Keychain for Linux (icp)"
command -v python3 >/dev/null || die "'python3' not found. Please install it."
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install --upgrade pip >/dev/null
"$ROOT/.venv/bin/pip" install -e "$ROOT"
chmod +x "$ROOT/host/icp-host.sh" "$ROOT/host/install.sh"

step "Setting up omnisette-server (local Anisette v3, Rust)"
if [[ ! -d "$OMNI_DIR" ]]; then
  die "omnisette-server/ not found in $ROOT"
fi

# Fetch Apple Music APK libraries required by omnisette (if not already present)
if [[ ! -f "$OMNI_DIR/lib/x86_64/libstoreservicescore.so" && ! -f "$OMNI_DIR/lib/arm64-v8a/libstoreservicescore.so" ]]; then
  if command -v curl >/dev/null && command -v unzip >/dev/null; then
    info "Downloading Apple Music APK to extract required libraries..."
    curl -fL --progress-bar -o "$OMNI_DIR/applemusic.apk" \
      "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk" \
      || warn "Could not download Apple Music APK; omnisette-server may not work until libs are provided."
    if [[ -f "$OMNI_DIR/applemusic.apk" ]]; then
      unzip -oq "$OMNI_DIR/applemusic.apk" 'lib/*/libstoreservicescore.so' 'lib/*/libCoreADI.so' -d "$OMNI_DIR" || true
      rm -f "$OMNI_DIR/applemusic.apk"
    fi
  else
    warn "curl/unzip not found; skipping APK library extraction. See omnisette-server/README.md."
  fi
else
  info "omnisette libraries already present"
fi

if command -v cargo >/dev/null; then
  info "Building omnisette-server (cargo build --release)..."
  (cd "$OMNI_DIR" && cargo build --release)
else
  warn "cargo not found; skipping Rust build. Install Rust (https://rustup.rs) and run: (cd omnisette-server && cargo build --release)"
fi

step "Done"
printf '\n\033[32m✓ Setup complete.\033[0m\n\n'
printf 'iCloud Keychain for Linux (icp):\n'
printf '  Activate: source %s/.venv/bin/activate\n' "$ROOT"
printf '  Login:    export ICP_ANISETTE_URL="http://localhost:6969" && icp login\n'
printf '  Browser host: %s/host/install.sh [CHROME_EXTENSION_ID]\n\n' "$ROOT"
printf 'omnisette-server (local Anisette v3):\n'
if [[ -x "$OMNI_DIR/target/release/omnisette-server" ]]; then
  printf '  Run:      %s/target/release/omnisette-server\n' "$OMNI_DIR"
else
  printf '  Build/run: see %s/README.md (requires Rust/cargo and extracted APK libs)\n' "$OMNI_DIR"
fi
printf '  Then set: export ICP_ANISETTE_URL="http://localhost:6969"\n\n'
