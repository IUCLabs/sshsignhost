#!/usr/bin/env bash
#
# Run the Vault integration suite against a throwaway dev-mode Vault.
# Set SSHSIGNHOST_TEST_VAULT_ADDR (and VAULT_TOKEN) to reuse a running server;
# otherwise a container is started and removed again.
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

GO_TEST=(go test -tags=integration -count=1 -v -run TestIntegration ./...)

if [ -n "${SSHSIGNHOST_TEST_VAULT_ADDR:-}" ]; then
  exec "${GO_TEST[@]}"
fi

RUNTIME="${CONTAINER_RUNTIME:-}"
if [ -z "${RUNTIME}" ]; then
  for candidate in docker podman; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      RUNTIME="${candidate}"
      break
    fi
  done
fi
if [ -z "${RUNTIME}" ]; then
  echo "ERROR: need docker or podman, or set SSHSIGNHOST_TEST_VAULT_ADDR" >&2
  exit 1
fi

IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.20}"
PORT="${VAULT_PORT:-8200}"
NAME="sshsignhost-vault-$$"
TOKEN="dev-root-token"

cleanup() { "${RUNTIME}" rm -f "${NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"${RUNTIME}" run -d --rm --name "${NAME}" \
  -p "127.0.0.1:${PORT}:8200" \
  -e "VAULT_DEV_ROOT_TOKEN_ID=${TOKEN}" \
  -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  "${IMAGE}" >/dev/null

# The suite polls /v1/sys/health itself, so there is nothing to sleep on here.
export SSHSIGNHOST_TEST_VAULT_ADDR="http://127.0.0.1:${PORT}"
export VAULT_TOKEN="${TOKEN}"
"${GO_TEST[@]}"
