#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/agent-native-private-vault-broker-approval-tests.XXXXXX")"
trap 'rm -rf "$OUTPUT"' EXIT
ARCHITECTURES="${PRIVATE_VAULT_BUILD_ARCHITECTURES:-universal}"
if [[ "$ARCHITECTURES" != "universal" && "$ARCHITECTURES" != "arm64" ]]; then
  echo "Broker replacement approval test architectures must be universal or arm64" >&2
  exit 1
fi

PRIVATE_VAULT_BUILD_ARCHITECTURES="$ARCHITECTURES" \
PRIVATE_VAULT_BUILD_BROKER_REPLACEMENT_APPROVAL_TESTS=1 \
  bash "$ROOT/native/build-private-vault-service.sh" "$OUTPUT" >/dev/null
"$OUTPUT/.broker-replacement-approval-tests/private-vault-broker-replacement-approval-tests-arm64"
if [[ "$ARCHITECTURES" == "universal" ]]; then
  arch -x86_64 "$OUTPUT/.broker-replacement-approval-tests/private-vault-broker-replacement-approval-tests-x86_64"
fi
