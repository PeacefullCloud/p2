#!/usr/bin/env bash
# Run p2 locally without Docker.
# Usage: bash scripts/run_without_docker.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}==>${NC} $*"; }
warn() { echo -e "${YELLOW}WARN:${NC} $*"; }
die()  { echo -e "\033[0;31mERROR:${NC} $*" >&2; exit 1; }

cd "$REPO_ROOT"

# ── Environment Setup ─────────────────────────────────────────────────────────
if [[ ! -f "$REPO_ROOT/.env" ]]; then
    if [[ -f "$REPO_ROOT/.env.example" ]]; then
        info "No .env file found. Creating one automatically from .env.example..."
        cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
    else
        die "No .env file found, and .env.example is missing!"
    fi
fi

_get_env_value() {
    local key="$1"
    local file="${2:-$REPO_ROOT/.env}"
    local val=""
    if [[ -f "$file" ]]; then
        val="$(grep -E "^${key}=" "$file" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
    fi
    echo "$val"
}

_set_env_value() {
    local key="$1"
    local value="$2"
    local env_file="$REPO_ROOT/.env"
    local escaped

    escaped="$(printf '%s' "$value" | sed 's/[\/&]/\\&/g')"
    if grep -q -E "^${key}=" "$env_file"; then
        sed -i "s/^${key}=.*/${key}=${escaped}/" "$env_file"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$env_file"
    fi
}

_set_env_default() {
    local key="$1"
    local value="$2"
    local current

    current="$(_get_env_value "$key")"
    if [[ -n "$current" ]]; then
        info "Preserving .env ${key}=${current}"
        return
    fi

    info "Setting native default ${key}=${value}"
    _set_env_value "$key" "$value"
}

# Like _set_env_default, but values matching the placeholder regex ($3) are
# treated as "unset" and rewritten with the native default. Compose overrides
# these to the `redis` service name via `environment:`, so .env keeps Docker
# values by default — but outside compose that hostname has no DNS entry, so
# every Redis client hangs on connect until it times out.
_set_env_default_native() {
    local key="$1"
    local value="$2"
    local placeholder_re="$3"
    local current

    current="$(_get_env_value "$key")"
    if [[ -n "$current" && ! "$current" =~ $placeholder_re ]]; then
        info "Preserving .env ${key}=${current}"
        return
    fi

    if [[ -n "$current" ]]; then
        info "Replacing Docker placeholder .env ${key}=${current} -> ${value}"
    else
        info "Setting native default ${key}=${value}"
    fi
    _set_env_value "$key" "$value"
}

_generate_secret_key() {
    if command -v python3 &>/dev/null; then
        python3 -c 'import secrets; print(secrets.token_urlsafe(64))'
    elif command -v openssl &>/dev/null; then
        openssl rand -base64 64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
    else
        die "Cannot generate P2_SECRET_KEY automatically: install python3 or openssl."
    fi
}

_generate_fernet_key() {
    if command -v python3 &>/dev/null; then
        python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
    elif command -v openssl &>/dev/null; then
        openssl rand -base64 32 | tr -d '\n' | tr '+/' '-_'
    else
        die "Cannot generate P2_FERNET_KEY automatically: install python3 or openssl."
    fi
}

_ensure_generated_secret() {
    local key="$1"
    local current="$(_get_env_value "$key")"

    if [[ -n "$current" && "$current" != change-me-* && "$current" != CHANGE-ME-* ]]; then
        return
    fi

    if [[ "$key" == "P2_SECRET_KEY" ]]; then
        info "Generating $key..."
        _set_env_value "$key" "$(_generate_secret_key)"
    elif [[ "$key" == "P2_FERNET_KEY" ]]; then
        info "Generating $key..."
        _set_env_value "$key" "$(_generate_fernet_key)"
    fi
}

# ── Resolve storage root ────────────────────────────────────────────────────────
_resolve_storage_root() {
    local env_file="$REPO_ROOT/.env"
    local val=""
    if [[ -f "$env_file" ]]; then
        val="$(grep -E '^P2_STORAGE__ROOT=' "$env_file" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
    fi
    if [[ -z "$val" && -f "$REPO_ROOT/.env.example" ]]; then
        val="$(grep -E '^P2_STORAGE__ROOT=' "$REPO_ROOT/.env.example" | tail -1 | cut -d= -f2- | tr -d '[:space:]')"
    fi
    if [[ -z "$val" || "$val" == "/storage" ]]; then
        val="$REPO_ROOT/storage"
    fi
    if [[ "$val" != /* ]]; then
        val="$REPO_ROOT/$val"
    fi
    echo "$val"
}

STORAGE_ROOT="$(_resolve_storage_root)"

# ── Dirs ───────────────────────────────────────────────────────────────────────
info "Creating required directories..."
mkdir -p "$STORAGE_ROOT/volumes" static

# ── Build Frappe UI SPA ────────────────────────────────────────────────────────
UI_DIR="$REPO_ROOT/ui"
if [ -f "$UI_DIR/package.json" ]; then
    if [ -d "$UI_DIR/dist" ]; then
        info "Frappe UI build directory already exists ($UI_DIR/dist) — skipping SPA build."
    else
        info "Building Frappe UI SPA..."
        cd "$UI_DIR"
        if [ ! -d "node_modules" ]; then
            npm install --silent 2>/dev/null || warn "npm install had warnings; continuing."
        fi
        npm run build 2>&1 | grep -E '(error|built|✓|✗)' || true
        cd "$REPO_ROOT"
        if [ -f "$UI_DIR/dist/index.html" ]; then
            info "Frappe UI build complete: $(du -sh "$UI_DIR/dist" | cut -f1)"
        else
            warn "Frappe UI build may have failed — check $UI_DIR for errors"
        fi
    fi
else
    warn "Frappe UI not found at $UI_DIR — skipping SPA build"
fi

info "Applying native-mode defaults without overwriting user settings..."
_ensure_generated_secret "P2_SECRET_KEY"
_ensure_generated_secret "P2_FERNET_KEY"

# /storage is the Docker-image default and does not point at this checkout.
# Normalize only that placeholder; preserve any real user-selected storage root.
CONFIGURED_STORAGE_ROOT="$(_get_env_value "P2_STORAGE__ROOT")"
if [[ -z "$CONFIGURED_STORAGE_ROOT" || "$CONFIGURED_STORAGE_ROOT" == "/storage" ]]; then
    info "Setting native storage root to $STORAGE_ROOT"
    _set_env_value "P2_STORAGE__ROOT" "$STORAGE_ROOT"
else
    info "Preserving .env P2_STORAGE__ROOT=$CONFIGURED_STORAGE_ROOT"
fi

_set_env_default_native "P2_REDIS__HOST" "127.0.0.1" '^redis$'
_set_env_default_native "P2_REDIS__ARQ_URL" "redis://127.0.0.1:6379/1" '^rediss?://redis([:/]|$)'
# P2_REDIS__URL is optional (settings falls back to redis.host), so only
# rewrite it when a Docker placeholder is actually present.
_p2_redis_url="$(_get_env_value "P2_REDIS__URL")"
if [[ "$_p2_redis_url" =~ ^rediss?://redis([:/]|$) ]]; then
    _set_env_default_native "P2_REDIS__URL" "redis://127.0.0.1:6379/0" '^rediss?://redis([:/]|$)'
fi
_set_env_default "P2_STORAGE__VOLUME_SIZE_BYTES" "104857600"
_set_env_default "P2_STORAGE__VOLUME_ACTIVE_POOL_SIZE" "2"
_set_env_default "P2_SECURITY__SSL_REDIRECT" "false"

# Granian serves everything directly (S3 data plane, Django, and the SPA).
# The X-Accel-Redirect handoff and its P2_STORAGE__USE_X_ACCEL_REDIRECT flag were
# removed along with the nginx dependency; a leftover entry in .env is inert.

# ── Port ───────────────────────────────────────────────────────────────────────
PORT=8787
INTERFACE="${P2_GRANIAN_INTERFACE:-$(_get_env_value "P2_GRANIAN_INTERFACE")}"
INTERFACE="${INTERFACE:-rsgi}"
case "$INTERFACE" in
    rsgi) APP="p2.core.rsgi:application" ;;
    asginl) APP="p2.core.asgi:application" ;;
    *) die "P2_GRANIAN_INTERFACE must be rsgi or asginl; got: $INTERFACE" ;;
esac

# ── Dependencies ───────────────────────────────────────────────────────────────
info "Syncing dependencies..."
# --inexact: the two Rust extensions (p2-s3-crypto, p2-s3-checksum) are built
# from p2/s3/*_ext and are deliberately not in pyproject.toml/uv.lock, so a
# plain `uv sync` considers them extraneous and uninstalls them on every run.
# --inexact leaves packages it does not manage alone.
uv sync --python 3.12 --inexact

# Rebuild Rust extensions after uv sync (which may have uninstalled them).
#
# This previously built only rust_ext, so p2_s3_checksum was never installed
# into the venv and p2.s3.checksum silently ran its pure-Python fallback.
# Delegate to the canonical builder so both extensions are always built and
# verified together.
info "Building Rust extensions..."
bash "$REPO_ROOT/scripts/build_rust_ext.sh"

if ! command -v redis-cli &>/dev/null; then
    warn "redis-cli not found; cannot verify local Dragonfly/Redis availability."
else
    if ! redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1; then
        die "No local Dragonfly/Redis server is reachable at 127.0.0.1:6379. Start it first, then rerun this script."
    fi
fi

export DJANGO_SETTINGS_MODULE="p2.core.settings"
export P2_STORAGE__ROOT="$STORAGE_ROOT"

# ── Django setup ───────────────────────────────────────────────────────────────
info "Running migrations..."
uv run python manage.py migrate --noinput

info "Collecting static files..."
uv run python manage.py collectstatic --noinput

# ── Launch ─────────────────────────────────────────────────────────────────────
# Raise the descriptor limit for high concurrency across configured workers.
ulimit -n 65536 2>/dev/null || true
umask 022

info "Starting arq worker..."
uv run --env-file .env python -m arq p2.core.worker.WorkerSettings &
WORKER_PID=$!

info "Starting gRPC server..."
uv run --env-file .env python manage.py grpc &
GRPC_PID=$!

CORES=$(nproc)
WORKERS="$(_get_env_value "P2_GRANIAN_WORKERS")"
if [[ -z "$WORKERS" ]]; then
    WORKERS="$CORES"
elif ! [[ "$WORKERS" =~ ^[1-9][0-9]*$ ]]; then
    die "P2_GRANIAN_WORKERS must be a positive integer; got: $WORKERS"
fi
info "Starting granian (${WORKERS} workers; ${CORES} CPU cores)..."
info "Using $INTERFACE interface ($APP)"
IS_DEBUG=false
if grep -iq '^P2_DEBUG=true' .env 2>/dev/null; then
    IS_DEBUG=true
fi

GRANIAN_ARGS=(
    --interface "$INTERFACE"
    --workers "$WORKERS"
    --loop uvloop
    --host 0.0.0.0
    --port "$PORT"
    --env-files .env
    --no-ws
    --working-dir "$REPO_ROOT"
)

if [[ "$IS_DEBUG" == "true" ]]; then
    GRANIAN_ARGS+=(--log --access-log --log-level info)
else
    GRANIAN_ARGS+=(--log --log-level error)
fi

uv run granian "${GRANIAN_ARGS[@]}" "$APP" &
SERVER_PID=$!

# ── Cleanup on exit ────────────────────────────────────────────────────────────
trap "info 'Shutting down...'; kill $WORKER_PID $SERVER_PID $GRPC_PID 2>/dev/null; wait" SIGINT SIGTERM

info "p2 running at http://localhost:$PORT (granian) — Ctrl+C to stop"
wait
