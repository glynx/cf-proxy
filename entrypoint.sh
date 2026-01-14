#!/bin/bash
set -Eeuo pipefail

# ---------- Defaults (override via env) ----------
: "${WORKDIR:=/cf-proxy/worker}"                    # your project dir (wrangler.toml lives here)
: "${WRANGLER_DISABLE_METRICS:=true}"               # avoid telemetry hangs in containers
: "${WRANGLER_LOG_SANITIZE:=true}"                  # set to false to see headers in logs
: "${NODE_OPTIONS:=--dns-result-order=ipv4first}"   # IPv4 first helps with odd DNS/IPv6 stalls
: "${NO_COLOR:=1}"                                  # no spinners/ANSI
: "${CI:=1}"                                        # non-interactive mode
: "${WRANGLER_SEND_METRICS:=false}"

# optional token substitution before deploy:
: "${AUTH_TOKEN_FILE:=/workspace/auth_token}"       # file holding your auth token
: "${WORKER_NAME_FILE:=/workspace/worker_name.txt}" # file holding your worker name
: "${TOKEN_PLACEHOLDER:=<YOUR-AUTH-TOKEN>}"         # placeholder string in your source
: "${TARGET_JS:=src/index.js}"                      # relative to $WORKDIR

# CA refresh policy
: "${CA_BUNDLE:=/etc/ssl/certs/ca-certificates.crt}"
: "${CA_SYMLINK:=/etc/ssl/cert.pem}"
: "${CA_REFRESH_DAYS:=7}"                           # refresh if bundle older than N days
: "${SSL_CERT_FILE:=${CA_BUNDLE}}"

# ---------- Helpers ----------
msg()  { printf '%s\n' "$*" >&2; }
die()  { msg "ERROR: $*"; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency '$1'. Install it in the image."
}

print_help() {
  cat <<'EOF'
Usage: entrypoint.sh <subcommand>

Subcommands:
  login        - Interactive OAuth login
  deploy       - Deploy the Cloudflare Worker
  undeploy     - Delete the worker from Cloudflare
  proxy        - Run cf-proxy for your worker
  get-hostname - Print <name>.<subdomain>.workers.dev
EOF
}

# ---------- CA handling ----------
ca_needs_refresh() {
  # needs refresh if missing/empty or older than CA_REFRESH_DAYS
  if [ ! -s "$CA_BUNDLE" ]; then
    return 0
  fi
  # If days is 0, always refresh
  if [ "${CA_REFRESH_DAYS}" = "0" ]; then
    return 0
  fi
  if find "$CA_BUNDLE" -mtime +"${CA_REFRESH_DAYS}" -print -quit | grep -q .; then
    return 0
  fi
  return 1
}

refresh_ca() {
  msg "[ca] refreshing CA bundle (apk + update-ca-certificates)..."
  need apk
  apk update >/dev/null
  # -U: upgrade if present; --no-cache to avoid stale index layers
  apk add -U --no-cache ca-certificates >/dev/null
  update-ca-certificates
  ln -sf "$CA_BUNDLE" "$CA_SYMLINK"
  export SSL_CERT_FILE="$CA_BUNDLE"
  # sanity checks
  [ -s "$CA_BUNDLE" ] || die "[ca] $CA_BUNDLE missing or empty after update"
  [ -e "$CA_SYMLINK" ] || die "[ca] $CA_SYMLINK symlink missing"
  # quick TLS probe to CF API (fail fast)
  if command -v curl >/dev/null 2>&1; then
    if ! curl -sS --fail https://api.cloudflare.com/client/v4/ips >/dev/null; then
      die "[ca] TLS probe to Cloudflare API failed – check network/proxy"
    fi
  fi
  msg "[ca] CA bundle ready ($CA_BUNDLE)"
}

ensure_ca() {
  # Always ensure the cert.pem symlink exists
  [ -e "$CA_SYMLINK" ] || ln -sf "$CA_BUNDLE" "$CA_SYMLINK" || true
  export SSL_CERT_FILE="$CA_BUNDLE"
  if ca_needs_refresh; then
    refresh_ca
  else
    # still do a lightweight sanity check
    [ -s "$CA_BUNDLE" ] || refresh_ca
  fi
}

# ---------- Wrangler helpers ----------
wrangler_cmd() {
  # prefer `wrangler` if present; otherwise `npx wrangler@latest`
  if command -v wrangler >/dev/null 2>&1; then
    WRANGLER_BIN="wrangler"
  else
    need npx
    WRANGLER_BIN="npx wrangler@latest"
  fi
  # enforce non-interactive, no ANSI
  env CI="$CI" NO_COLOR="$NO_COLOR" WRANGLER_SEND_METRICS="$WRANGLER_SEND_METRICS" $WRANGLER_BIN "$@"
}

get_worker_name() {
  awk -F\" '/^[[:space:]]*name[[:space:]]*=/ {print $2; exit}' "${WORKDIR}/wrangler.toml"
}

get_access_token() {
  awk -F\" '/^oauth_token[[:space:]]*=/ {print $2; exit}' \
    "${XDG_CONFIG_HOME}/.wrangler/config/default.toml"
}

get_account_id_from_whoami() {
  wrangler_cmd whoami | grep -oE '[0-9a-f]{32}' | head -1
}

get_workers_subdomain() {
  local cache_dir="${XDG_CONFIG_HOME}/.cfproxy"
  local cache_file="${cache_dir}/subdomain.txt"

  # 1) Try to read from cache if file exists and is non-empty
  if [ -s "$cache_file" ]; then
    local cached
    cached="$(head -n1 "$cache_file" | tr -d '\r\n')"
    # Subdomain should normally match [a-z0-9-]+ (without ".workers.dev")
    if printf '%s' "$cached" | grep -Eq '^[a-z0-9-]+$'; then
      echo "$cached"
      return 0
    else
      msg "[cache] Ignoring invalid subdomain in cache: '$cached' → fetching fresh value"
    fi
  fi

  # 2) If no valid cache, fetch via Cloudflare API
  local acc access sub
  acc="$(get_account_id_from_whoami)"
  [ -n "$acc" ] || die "Could not extract Account ID from 'wrangler whoami'. Are you logged in?"

  access="$(get_access_token)"
  [ -n "$access" ] || die "Could not read oauth_token from ${XDG_CONFIG_HOME}/.wrangler/config/default.toml"

  sub="$(
    curl -fsS -H "Authorization: Bearer $access" \
      "https://api.cloudflare.com/client/v4/accounts/$acc/workers/subdomain" \
    | jq -r '.result.subdomain'
  )"

  # 3) Validate and store in cache
  [ -n "$sub" ] || die "Cloudflare API returned empty subdomain"
  printf '%s' "$sub" | grep -Eq '^[a-z0-9-]+$' \
    || die "Cloudflare API returned unexpected subdomain: '$sub'"

  mkdir -p "$cache_dir"
  if ! printf '%s\n' "$sub" >"$cache_file"; then
    msg "[cache] Warning: could not write cache file: $cache_file"
  fi

  echo "$sub"
}

replace_placeholder_if_present() {
  local src="${WORKDIR}/${TARGET_JS}"
  if [ -f "$AUTH_TOKEN_FILE" ] && [ -f "$src" ]; then
    local token
    token="$(cat "$AUTH_TOKEN_FILE")"
    sed -i "s|${TOKEN_PLACEHOLDER}|${token}|g" "$src"
  else
    msg "Skip token replacement (missing ${AUTH_TOKEN_FILE} or ${src})"
  fi

  if [ -f "$WORKER_NAME_FILE" ] && [ -f "${WORKDIR}/wrangler.toml" ]; then
    local name
    name="$(cat "$WORKER_NAME_FILE")"
    sed -i "s|test|${name}|g" "${WORKDIR}/wrangler.toml"
  else
    msg "Skip worker name replacement (missing ${WORKER_NAME_FILE} or ${WORKDIR}/wrangler.toml)"
  fi
}

cmd_login() {
  ensure_ca
  mkdir -p "${XDG_CONFIG_HOME}/.wrangler/config"
  msg "Starting interactive OAuth login..."
  wrangler_cmd login
  msg "Login complete."
  msg "Whoami:"
  wrangler_cmd whoami || true
}

cmd_deploy() {
  ensure_ca
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  replace_placeholder_if_present
  ( cd "$WORKDIR" && wrangler_cmd deploy )
  # Optional: print workers.dev URL
  local name sub
  name="$(get_worker_name || true)"
  if [ -n "${name:-}" ]; then
    sub="$(get_workers_subdomain || true)"
    [ -n "${sub:-}" ] && msg "Deployed: https://${name}.${sub}.workers.dev"
  fi
}

cmd_undeploy() {
  ensure_ca
  replace_placeholder_if_present
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  ( cd "$WORKDIR" && wrangler_cmd delete )
}

cmd_proxy() {
  ensure_ca
  replace_placeholder_if_present
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  cd "${WORKDIR}/.."
  python3 proxy.py socks -a "$(cat "$AUTH_TOKEN_FILE")" -p 1080 --host 127.0.0.1 --worker "$(get_worker_name).$(get_workers_subdomain).workers.dev"
}

cmd_get_hostname() {
  ensure_ca
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  echo "$(get_worker_name).$(get_workers_subdomain).workers.dev"
}

# ---------- Main ----------
SUBCMD="${1:-}"

export XDG_CONFIG_HOME
export WRANGLER_DISABLE_METRICS
export WRANGLER_LOG
export WRANGLER_LOG_PATH
export WRANGLER_LOG_SANITIZE
export NODE_OPTIONS
export NO_COLOR
export CI
export WRANGLER_SEND_METRICS
export SSL_CERT_FILE

case "$SUBCMD" in
  login)        shift; cmd_login "$@";;
  deploy)       shift; cmd_deploy "$@";;
  undeploy)     shift; cmd_undeploy "$@";;
  proxy)        shift; cmd_proxy "$@";;
  get-hostname) shift; cmd_get_hostname "$@";;
  ""|help|-h|--help) print_help ;;
  *) die "Unknown subcommand: ${SUBCMD}. Run with no args for help." ;;
esac