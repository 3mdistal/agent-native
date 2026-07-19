#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/agent-native-private-vault-continuity-coordinator-tests.XXXXXX")"
trap 'rm -rf "$OUTPUT"' EXIT

PRIVATE_VAULT_BUILD_CONTINUITY_COORDINATOR_TESTS=1 \
  bash "$ROOT/native/build-private-vault-service.sh" "$OUTPUT" >/dev/null

DIRECTORY="$OUTPUT/.continuity-coordinator-tests"
"$DIRECTORY/private-vault-continuity-coordinator-tests-arm64"
arch -x86_64 "$DIRECTORY/private-vault-continuity-coordinator-tests-x86_64"
