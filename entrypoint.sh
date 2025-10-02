#!/bin/bash
set -Eeuo pipefail

# ---------- Defaults (override via env) ----------
: "${WORKDIR:=/cf-proxy/worker}"                    # your project dir (wrangler.toml lives here)
: "${WRANGLER_DISABLE_METRICS:=true}"               # avoid telemetry hangs in containers
: "${WRANGLER_LOG_SANITIZE:=true}"                  # set to false to see headers in logs
: "${NODE_OPTIONS:=--dns-result-order=ipv4first}"   # IPv4 first helps with odd DNS/IPv6 stalls

# optional token substitution before deploy:
: "${AUTH_TOKEN_FILE:=/workspace/auth_token}"       # file holding your auth token
: "${WORKER_NAME_FILE:=/workspace/worker_name.txt}" # file holding your worker name
: "${TOKEN_PLACEHOLDER:=<YOUR-AUTH-TOKEN>}"         # placeholder string in your source
: "${TARGET_JS:=src/index.js}"                      # relative to $WORKDIR

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
  login      - Interactive OAuth login 
  deploy     - Deploy the Cloudflare Worker
  undeploy   - Delete the worker from Cloudflare
  proxy      - Run cf-proxy for your worker
EOF
}

get_worker_name() {
  # pulls `name = "..."` from wrangler.toml
  awk -F\" '/^[[:space:]]*name[[:space:]]*=/ {print $2; exit}' "${WORKDIR}/wrangler.toml"
}

get_access_token() {
  awk -F\" '/^oauth_token[[:space:]]*=/ {print $2; exit}' \
    "${XDG_CONFIG_HOME}/.wrangler/config/default.toml"
}

get_account_id_from_whoami() {
  # wrangler whoami prints a box table; pull first 32-hex id
  wrangler whoami | grep -oE '[0-9a-f]{32}' | head -1
}

get_workers_subdomain() {
  local acc access
  acc="$(get_account_id_from_whoami)"
  [ -n "$acc" ] || die "Could not extract Account ID from 'wrangler whoami'. Are you logged in?"
  access="$(get_access_token)"
  [ -n "$access" ] || die "Could not read oauth_token from ${XDG_CONFIG_HOME}/.wrangler/config/default.toml"

  curl -fsS -H "Authorization: Bearer $access" \
	"https://api.cloudflare.com/client/v4/accounts/$acc/workers/subdomain" |
	jq -r '.result.subdomain'
}

replace_placeholder_if_present() {
  local src="${WORKDIR}/${TARGET_JS}"
  if [ -f "$AUTH_TOKEN_FILE" ] && [ -f "$src" ]; then
    local token
    token="$(cat "$AUTH_TOKEN_FILE")"
    # Use '|' as sed delimiter to avoid collisions
    sed -i "s|${TOKEN_PLACEHOLDER}|${token}|g" "$src"
  else
    msg "Skip token replacement (missing ${AUTH_TOKEN_FILE} or ${src})"
  fi

  if [ -f "$WORKER_NAME_FILE" ] && [ -f "${WORKDIR}/wrangler.toml" ]; then
    local name
    name="$(cat "$WORKER_NAME_FILE")"
    # Use '|' as sed delimiter to avoid collisions
    sed -i "s|test|${name}|g" "${WORKDIR}/wrangler.toml"
  else
    msg "Skip token replacement (missing ${$WORKER_NAME_FILE} or ${WORKDIR}/wrangler.toml)"
  fi
}

cmd_login() {
  mkdir -p "${XDG_CONFIG_HOME}/.wrangler/config"
  msg "Starting interactive OAuth login..."
  wrangler login
  msg "Login complete."
  msg "Whoami:"
  wrangler whoami || true
}

cmd_deploy() {
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  replace_placeholder_if_present
  ( cd "$WORKDIR" && wrangler deploy )
  # Optional: print workers.dev URL for convenience
  local name sub
  name="$(get_worker_name || true)"
  if [ -n "${name:-}" ]; then
    sub="$(get_workers_subdomain || true || true)"
    [ -n "${sub:-}" ] && msg "Deployed: https://${name}.${sub}.workers.dev"
  fi
}

cmd_undeploy() {
  replace_placeholder_if_present
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  ( cd "$WORKDIR" && wrangler delete)
}

cmd_proxy() {
  replace_placeholder_if_present
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  cd ${WORKDIR}/..
  python3 proxy.py socks -a $(cat $AUTH_TOKEN_FILE) -p 1080 --host 127.0.0.1 --worker $(get_worker_name).$(get_workers_subdomain).workers.dev
}

cmd_get_hostname() {
  replace_placeholder_if_present
  [ -f "${WORKDIR}/wrangler.toml" ] || die "wrangler.toml not found in ${WORKDIR}"
  echo $(get_worker_name).$(get_workers_subdomain).workers.dev
}
# ---------- Main ----------
SUBCMD="${1:-}"

export XDG_CONFIG_HOME
export WRANGLER_DISABLE_METRICS
export WRANGLER_LOG
export WRANGLER_LOG_PATH
export WRANGLER_LOG_SANITIZE
export NODE_OPTIONS

case "$SUBCMD" in
  login)    shift; cmd_login "$@";;
  deploy)   shift; cmd_deploy "$@";;
  undeploy) shift; cmd_undeploy "$@";;
  proxy)    shift; cmd_proxy "$@";;
  get-hostname)    shift; cmd_get_hostname "$@";;
  ""|help|-h|--help) print_help ;;
  *) die "Unknown subcommand: ${SUBCMD}. Run with no args for help." ;;
esac
